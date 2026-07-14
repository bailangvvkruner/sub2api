mod provider;
mod zip;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{AuthError, extract_api_key, validate_api_key_snapshot},
    billing::Decimal,
    gateway::GatewayRuntime,
    repository::{AccountRecord, CoreRepository},
};

use self::{
    provider::{ProviderBatch, ProviderClient, ProviderState},
    zip::ZipBuilder,
};

const MAX_ITEMS: usize = 200;
const MAX_OUTPUTS_PER_ITEM: usize = 4;
const MAX_PROMPT_CHARS: usize = 8_000;
const MAX_REFERENCE_BYTES: usize = 10 * 1024 * 1024;
const MAX_REFERENCE_BYTES_PER_JOB: usize = 128 * 1024 * 1024;
const MAX_PROVIDER_OUTPUT_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_IMAGE_SIZE: &str = "1K";
const DEFAULT_RESPONSE_MIME: &str = "image/png";
const DEFAULT_DISCOUNT: &str = "0.5";
const DEFAULT_HOLD_MULTIPLIER: &str = "0.6";
const WORKER_INTERVAL: Duration = Duration::from_secs(30);
const MODEL_PRICES: &str =
    include_str!("../../resources/model-pricing/model_prices_and_context_window.json");

const JOB_COLUMNS: &str = r"
    id,
    batch_id,
    user_id,
    api_key_id,
    account_id,
    provider,
    model,
    task_name,
    parent_batch_id,
    status,
    provider_job_name,
    provider_input_ref,
    provider_output_ref,
    item_count,
    success_count,
    fail_count,
    cancelled_count,
    estimated_cost::text AS estimated_cost,
    hold_amount::text AS hold_amount,
    actual_cost::text AS actual_cost,
    base_unit_price::text AS base_unit_price,
    group_rate_multiplier::text AS group_rate_multiplier,
    account_rate_multiplier::text AS account_rate_multiplier,
    batch_discount_multiplier::text AS batch_discount_multiplier,
    hold_multiplier::text AS hold_multiplier,
    billable_unit_price::text AS billable_unit_price,
    hold_unit_price::text AS hold_unit_price,
    pricing_snapshot_version,
    idempotency_key,
    request_hash,
    manifest_hash,
    retry_count,
    output_deleted_at IS NOT NULL AS output_deleted,
    user_deleted_at IS NOT NULL AS user_deleted,
    (EXTRACT(EPOCH FROM created_at))::bigint AS created_at,
    (EXTRACT(EPOCH FROM submitted_at))::bigint AS submitted_at,
    (EXTRACT(EPOCH FROM settled_at))::bigint AS settled_at,
    (EXTRACT(EPOCH FROM downloaded_at))::bigint AS downloaded_at,
    (EXTRACT(EPOCH FROM output_deleted_at))::bigint AS output_deleted_at,
    last_error_code,
    last_error_message
";

#[derive(Clone)]
pub struct BatchImageService {
    inner: Arc<BatchImageInner>,
}

struct BatchImageInner {
    pool: PgPool,
    repository: CoreRepository,
    provider: ProviderClient,
    gateway: Option<GatewayRuntime>,
}

impl BatchImageService {
    /// Builds the PostgreSQL-backed batch image service.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider HTTP client cannot be built.
    pub fn new(pool: PgPool, gateway: Option<GatewayRuntime>) -> Result<Self, reqwest::Error> {
        let provider = ProviderClient::new()?;
        Ok(Self {
            inner: Arc::new(BatchImageInner {
                repository: CoreRepository::new(pool.clone()),
                pool,
                provider,
                gateway,
            }),
        })
    }

    #[must_use]
    pub fn spawn_worker(&self) -> BatchImageWorker {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let service = self.clone();
        let task = tokio::spawn(async move {
            service.worker_loop(worker_cancellation).await;
        });
        BatchImageWorker { cancellation, task }
    }

    pub async fn handle(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
        client_ip: Option<&str>,
    ) -> Response {
        let route = match BatchRoute::classify(&method, uri.path()) {
            Ok(route) => route,
            Err(error) => return error.into_response(),
        };
        let owner = match self.authenticate(&headers, uri.query(), client_ip).await {
            Ok(owner) => owner,
            Err(error) => return error.into_response(),
        };
        let query = query_parameters(uri.query());
        let result = match route {
            BatchRoute::Submit => self
                .submit(&owner, &headers, &body)
                .await
                .map(json_response),
            BatchRoute::List => self.list(&owner, &query).await.map(json_response),
            BatchRoute::Models => self.models(&owner).await.map(json_response),
            BatchRoute::Get(batch_id) => self.get(&owner, &batch_id).await.map(json_response),
            BatchRoute::Items(batch_id) => self
                .items(&owner, &batch_id, &query)
                .await
                .map(json_response),
            BatchRoute::ItemContent {
                batch_id,
                custom_id,
            } => {
                self.item_content(&owner, &batch_id, &custom_id, &query)
                    .await
            }
            BatchRoute::Download(batch_id) => self.download(&owner, &batch_id, &query).await,
            BatchRoute::Cancel(batch_id) => self.cancel(&owner, &batch_id).await.map(json_response),
            BatchRoute::Delete(batch_id) => self
                .delete_record(&owner, &batch_id)
                .await
                .map(|()| StatusCode::NO_CONTENT.into_response()),
            BatchRoute::DeleteOutputs(batch_id) => self
                .delete_outputs(&owner, &batch_id)
                .await
                .map(json_response),
        };
        result.unwrap_or_else(IntoResponse::into_response)
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
        raw_query: Option<&str>,
        client_ip: Option<&str>,
    ) -> Result<Owner, BatchError> {
        let extracted = extract_api_key(headers, raw_query).map_err(AuthError::from)?;
        let snapshot = self
            .inner
            .repository
            .find_api_key_for_auth(&extracted.key)
            .await?
            .ok_or(AuthError::InvalidApiKey)?;
        validate_api_key_snapshot(&snapshot, client_ip, now_unix_seconds() * 1_000, true)?;
        let user = snapshot.user.as_ref().ok_or(AuthError::UserNotFound)?;
        Ok(Owner {
            user_id: user.id,
            api_key_id: snapshot.api_key.id,
            group_id: snapshot.api_key.group_id,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn submit(
        &self,
        owner: &Owner,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Value, BatchError> {
        let request: SubmitRequest = serde_json::from_slice(body).map_err(|_| {
            BatchError::bad_request("BATCH_IMAGE_INVALID_ITEMS", "batch image items are invalid")
        })?;
        let request = NormalizedRequest::new(request)?;
        self.ensure_group_enabled(owner).await?;
        let idempotency_key = headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .unwrap_or_default();
        if idempotency_key.len() > 255 {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_INVALID_ITEMS",
                "idempotency key is too long",
            ));
        }
        let request_hash = request.hash()?;
        if !idempotency_key.is_empty()
            && let Some(existing) = self.load_by_idempotency(owner, idempotency_key).await?
        {
            if existing.request_hash.as_deref() != Some(request_hash.as_str()) {
                return Err(BatchError::new(
                    StatusCode::CONFLICT,
                    "BATCH_IMAGE_IDEMPOTENCY_CONFLICT",
                    "idempotency key reused with different batch image request",
                ));
            }
            return Ok(existing.public_value());
        }

        let selection = self.select_account(owner, &request.model).await?;
        let pricing = self.pricing(owner, &request, &selection.account).await?;
        let batch_id = format!("imgbatch_{}", uuid::Uuid::new_v4().simple());
        let task_name = if request.task_name.is_empty() {
            Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
        } else {
            request.task_name.clone()
        };
        if let Some(parent) = request.parent_batch_id.as_deref() {
            self.load_job_for_owner(owner, parent).await?;
        }

        let mut transaction = self.inner.pool.begin().await?;
        if !idempotency_key.is_empty() {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(format!(
                    "batch-image:{}:{}:{}",
                    owner.user_id, owner.api_key_id, idempotency_key
                ))
                .execute(&mut *transaction)
                .await?;
            if let Some(existing) =
                load_by_idempotency_tx(&mut transaction, owner, idempotency_key).await?
            {
                transaction.rollback().await?;
                if existing.request_hash.as_deref() != Some(request_hash.as_str()) {
                    return Err(BatchError::new(
                        StatusCode::CONFLICT,
                        "BATCH_IMAGE_IDEMPOTENCY_CONFLICT",
                        "idempotency key reused with different batch image request",
                    ));
                }
                return Ok(existing.public_value());
            }
        }
        insert_job_and_hold(
            &mut transaction,
            owner,
            &batch_id,
            &task_name,
            &request,
            &selection,
            &pricing,
            idempotency_key,
            &request_hash,
        )
        .await?;
        insert_pending_items(&mut transaction, &batch_id, &request_hash, &request.items).await?;
        transaction.commit().await?;
        self.invalidate_auth_cache();

        let jsonl = request.gemini_jsonl(&selection.upstream_model)?;
        let provider_result = self
            .inner
            .provider
            .submit(
                &selection.base_url,
                &selection.api_key,
                &batch_id,
                &selection.upstream_model,
                jsonl,
            )
            .await;
        let provider_batch = match provider_result {
            Ok(provider_batch) => provider_batch,
            Err(error) => {
                self.fail_unsubmitted(&batch_id, owner.user_id, &pricing.hold_amount, &error)
                    .await?;
                return Err(error.public_submit_error());
            }
        };
        if let Err(error) = self.mark_submitted(&batch_id, &provider_batch).await {
            let cleanup = self
                .reconcile_submit_persistence_failure(&batch_id, &error)
                .await?;
            if cleanup {
                self.cleanup_orphan_submission(&selection, &provider_batch)
                    .await;
                return Err(error);
            }
        }
        self.load_job_for_owner(owner, &batch_id)
            .await
            .map(|job| job.public_value())
    }

    async fn list(
        &self,
        owner: &Owner,
        query: &HashMap<String, String>,
    ) -> Result<Value, BatchError> {
        let limit = query_limit(query, 20, 100)?;
        let offset = query_offset(query)?;
        let status = normalize_list_status(query.get("status").map(String::as_str))?;
        let task_name = query.get("task_name").map_or("", String::as_str).trim();
        let downloaded = parse_downloaded_filter(query.get("downloaded").map(String::as_str))?;
        let from = parse_time_filter(query.get("from").map(String::as_str))?;
        let to = parse_time_filter(query.get("to").map(String::as_str))?;
        let sql = format!(
            r"
SELECT {JOB_COLUMNS}
FROM batch_image_jobs
WHERE user_id = $1
  AND api_key_id = $2
  AND user_deleted_at IS NULL
  AND (
      $3 = ''
      OR ($3 = 'queued' AND status IN ('created', 'uploading', 'submitted'))
      OR ($3 <> 'queued' AND status = $3)
  )
  AND ($4 = '' OR task_name ILIKE '%' || $4 || '%')
  AND ($5::boolean IS NULL OR (downloaded_at IS NOT NULL) = $5)
  AND ($6::bigint IS NULL OR created_at >= TO_TIMESTAMP($6))
  AND ($7::bigint IS NULL OR created_at <= TO_TIMESTAMP($7))
ORDER BY created_at DESC, id DESC
LIMIT $8 OFFSET $9
"
        );
        let rows = sqlx::query(&sql)
            .bind(owner.user_id)
            .bind(owner.api_key_id)
            .bind(status)
            .bind(task_name)
            .bind(downloaded)
            .bind(from)
            .bind(to)
            .bind(i64::try_from(limit).unwrap_or(100))
            .bind(i64::try_from(offset).unwrap_or(i64::MAX))
            .fetch_all(&self.inner.pool)
            .await?;
        let data = rows
            .iter()
            .map(BatchJob::from_row)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|job| job.public_value())
            .collect::<Vec<_>>();
        Ok(json!({
            "object": "list",
            "has_more": data.len() == limit,
            "data": data,
        }))
    }

    async fn get(&self, owner: &Owner, batch_id: &str) -> Result<Value, BatchError> {
        let job = self.load_job_for_owner(owner, batch_id).await?;
        Ok(job.public_value())
    }

    async fn models(&self, owner: &Owner) -> Result<Value, BatchError> {
        let group = self.ensure_group_enabled(owner).await?;
        let accounts = self
            .inner
            .repository
            .list_schedulable_accounts("gemini", owner.group_id, now_unix_seconds() * 1_000)
            .await?;
        let mut models = HashSet::new();
        for account in accounts
            .iter()
            .filter(|account| provider_api_key(account).is_some())
        {
            let mapped = mapped_models(account);
            if mapped.is_empty() {
                models.extend(default_models().into_iter().map(str::to_owned));
            } else {
                models.extend(mapped);
            }
        }
        let mut models = models.into_iter().collect::<Vec<_>>();
        models.retain(|model| {
            group
                .as_ref()
                .and_then(|group| group.image_price(DEFAULT_IMAGE_SIZE))
                .is_some()
                || bundled_image_unit_price(model).is_some()
        });
        models.sort();
        Ok(json!({
            "object": "list",
            "data": models.into_iter().map(|model| json!({
                "id": model,
                "object": "image.batch.model",
                "provider": "gemini_api",
            })).collect::<Vec<_>>()
        }))
    }

    async fn items(
        &self,
        owner: &Owner,
        batch_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<Value, BatchError> {
        self.load_job_for_owner(owner, batch_id).await?;
        let limit = query_limit(query, 100, 500)?;
        let offset = query_offset(query)?;
        let status = normalize_item_status(query.get("status").map(String::as_str))?;
        let rows = sqlx::query(
            r"
SELECT
    custom_id,
    status,
    prompt_preview,
    mime_type,
    file_extension,
    image_count,
    error_code,
    error_message,
    provider_source_object
FROM batch_image_items
WHERE job_id = $1
  AND ($2 = '' OR status = $2)
ORDER BY id
LIMIT $3 OFFSET $4
",
        )
        .bind(batch_id)
        .bind(status)
        .bind(i64::try_from(limit).unwrap_or(500))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&self.inner.pool)
        .await?;
        let data = rows
            .iter()
            .map(public_item)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "object": "list",
            "has_more": data.len() == limit,
            "data": data,
        }))
    }

    async fn item_content(
        &self,
        owner: &Owner,
        batch_id: &str,
        custom_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<Response, BatchError> {
        let job = self.completed_job(owner, batch_id).await?;
        let image_index = query
            .get("image_index")
            .map_or(Ok(0), |value| value.parse::<usize>())
            .map_err(|_| {
                BatchError::bad_request(
                    "BATCH_IMAGE_ITEM_IMAGE_INDEX_OUT_OF_RANGE",
                    "batch image item image index is out of range",
                )
            })?;
        let row = sqlx::query(
            r"
SELECT status, mime_type, file_extension
FROM batch_image_items
WHERE job_id = $1 AND custom_id = $2
LIMIT 1
",
        )
        .bind(batch_id)
        .bind(custom_id)
        .fetch_optional(&self.inner.pool)
        .await?
        .ok_or_else(|| {
            BatchError::not_found("BATCH_IMAGE_ITEM_NOT_FOUND", "batch image item not found")
        })?;
        let status: String = row.try_get("status")?;
        if status != "success" {
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_ITEM_FAILED",
                "batch image item did not succeed",
            ));
        }
        let output = self.download_provider_output(&job).await?;
        let parsed = find_output_item(&output, custom_id)?.ok_or_else(|| {
            BatchError::internal(
                "BATCH_IMAGE_RESULT_MISSING",
                "batch image result is missing",
            )
        })?;
        let image = parsed.images.get(image_index).ok_or_else(|| {
            BatchError::bad_request(
                "BATCH_IMAGE_ITEM_IMAGE_INDEX_OUT_OF_RANGE",
                "batch image item image index is out of range",
            )
        })?;
        let bytes = BASE64.decode(image.data.as_bytes()).map_err(|_| {
            BatchError::internal(
                "BATCH_IMAGE_RESULT_MISSING",
                "batch image result is invalid",
            )
        })?;
        let extension = image.extension();
        let filename = safe_filename(custom_id, extension);
        let mut response = Body::from(bytes).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(&image.mime_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        );
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=300"),
        );
        self.mark_downloaded(batch_id).await;
        Ok(response)
    }

    #[allow(clippy::too_many_lines)]
    async fn download(
        &self,
        owner: &Owner,
        batch_id: &str,
        query: &HashMap<String, String>,
    ) -> Result<Response, BatchError> {
        let job = self.completed_job(owner, batch_id).await?;
        let max_items = query
            .get("max_items")
            .map_or(Ok(MAX_ITEMS), |value| value.parse::<usize>())
            .map_err(|_| {
                BatchError::bad_request(
                    "BATCH_IMAGE_ZIP_TOO_MANY_ITEMS",
                    "batch image ZIP contains too many items",
                )
            })?;
        if max_items == 0 || max_items > MAX_ITEMS {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_ZIP_TOO_MANY_ITEMS",
                "batch image ZIP contains too many items",
            ));
        }
        let output = self.download_provider_output(&job).await?;
        let parsed = parse_provider_output(&output)?;
        let rows = sqlx::query(
            r"
SELECT custom_id, status, error_code, error_message
FROM batch_image_items
WHERE job_id = $1
ORDER BY id
LIMIT $2
",
        )
        .bind(batch_id)
        .bind(i64::try_from(max_items).unwrap_or(i64::MAX))
        .fetch_all(&self.inner.pool)
        .await?;
        let mut zip = ZipBuilder::new();
        let mut files = Vec::new();
        let mut errors = Vec::new();
        for row in &rows {
            let custom_id: String = row.try_get("custom_id")?;
            let status: String = row.try_get("status")?;
            if status != "success" {
                errors.push(json!({
                    "custom_id": custom_id,
                    "code": row.try_get::<Option<String>, _>("error_code")?.unwrap_or_default(),
                    "message": sanitize_public_error(
                        row.try_get::<Option<String>, _>("error_message")?.as_deref().unwrap_or_default()
                    ),
                }));
                continue;
            }
            let Some(item) = parsed.get(&custom_id) else {
                errors.push(json!({
                    "custom_id": custom_id,
                    "code": "RESULT_MISSING",
                    "message": "provider result was not found for item",
                }));
                continue;
            };
            for (index, image) in item.images.iter().enumerate() {
                let Ok(bytes) = BASE64.decode(image.data.as_bytes()) else {
                    errors.push(json!({
                        "custom_id": custom_id,
                        "code": "IMAGE_DECODE_FAILED",
                        "message": "image data could not be decoded",
                    }));
                    continue;
                };
                let suffix = if index == 0 {
                    String::new()
                } else {
                    format!("_{}", index + 1)
                };
                let filename = format!(
                    "images/{}{}",
                    safe_filename(&custom_id, ""),
                    format_args!("{suffix}.{}", image.extension())
                );
                zip.add(filename.clone(), &bytes)?;
                files.push(json!({
                    "custom_id": custom_id,
                    "filename": filename,
                    "mime_type": image.mime_type,
                    "image_index": index,
                }));
            }
        }
        zip.add(
            "manifest.json".to_owned(),
            &serde_json::to_vec_pretty(&json!({
                "batch_id": job.batch_id,
                "model": job.model,
                "item_count": job.item_count,
                "success_count": job.success_count,
                "fail_count": job.fail_count,
                "files": files,
            }))?,
        )?;
        zip.add(
            "errors.json".to_owned(),
            &serde_json::to_vec_pretty(&errors)?,
        )?;
        let bytes = zip.finish()?;
        let mut response = Body::from(bytes).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/zip"),
        );
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{}.zip\"", job.batch_id))
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        self.mark_downloaded(batch_id).await;
        Ok(response)
    }

    async fn cancel(&self, owner: &Owner, batch_id: &str) -> Result<Value, BatchError> {
        let job = self.load_job_for_owner(owner, batch_id).await?;
        if job.is_terminal() {
            return Ok(job.public_value());
        }
        if let Some(provider_job_name) = job.provider_job_name.as_deref() {
            let account = self.load_account_for_job(&job).await?;
            let base_url = provider_base_url(&account);
            let api_key = provider_api_key(&account).ok_or_else(|| {
                BatchError::upstream(
                    "BATCH_IMAGE_PROVIDER_MISSING_API_KEY",
                    "batch image provider account has no API key",
                )
            })?;
            self.inner
                .provider
                .cancel(&base_url, &api_key, provider_job_name)
                .await
                .map_err(|error| error.public_cancel_error())?;
        }
        self.finish_without_charge(
            &job,
            "cancelled",
            "BATCH_IMAGE_CANCELLED",
            "batch image job cancelled",
        )
        .await?;
        self.load_job_for_owner(owner, batch_id)
            .await
            .map(|job| job.public_value())
    }

    async fn delete_record(&self, owner: &Owner, batch_id: &str) -> Result<(), BatchError> {
        let job = self.load_job_for_owner(owner, batch_id).await?;
        if !job.is_terminal() {
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_RECORD_DELETE_NOT_READY",
                "batch image record can only be deleted after the job finishes",
            ));
        }
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET user_deleted_at = COALESCE(user_deleted_at, NOW()), updated_at = NOW()
WHERE batch_id = $1 AND user_id = $2 AND api_key_id = $3
",
        )
        .bind(batch_id)
        .bind(owner.user_id)
        .bind(owner.api_key_id)
        .execute(&self.inner.pool)
        .await?;
        Ok(())
    }

    async fn delete_outputs(&self, owner: &Owner, batch_id: &str) -> Result<Value, BatchError> {
        let job = self.load_job_for_owner(owner, batch_id).await?;
        if !matches!(
            job.status.as_str(),
            "completed" | "failed" | "cancelled" | "output_deleted"
        ) {
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_OUTPUT_DELETE_NOT_READY",
                "batch image output can only be deleted after completion",
            ));
        }
        if !job.output_deleted {
            if let Some(output_ref) = job.provider_output_ref.as_deref() {
                let account = self.load_account_for_job(&job).await?;
                let base_url = provider_base_url(&account);
                let api_key = provider_api_key(&account).ok_or_else(|| {
                    BatchError::upstream(
                        "BATCH_IMAGE_PROVIDER_MISSING_API_KEY",
                        "batch image provider account has no API key",
                    )
                })?;
                self.inner
                    .provider
                    .delete_file(&base_url, &api_key, output_ref)
                    .await
                    .map_err(|error| error.public_cleanup_error())?;
            }
            sqlx::query(
                r"
UPDATE batch_image_jobs
SET output_deleted_at = COALESCE(output_deleted_at, NOW()),
    status = 'output_deleted',
    updated_at = NOW()
WHERE batch_id = $1
",
            )
            .bind(batch_id)
            .execute(&self.inner.pool)
            .await?;
        }
        self.load_job_for_owner(owner, batch_id)
            .await
            .map(|job| job.public_value())
    }

    async fn ensure_group_enabled(
        &self,
        owner: &Owner,
    ) -> Result<Option<GroupBatchConfig>, BatchError> {
        let Some(group_id) = owner.group_id else {
            return Ok(None);
        };
        let row = sqlx::query(
            r"
SELECT
    g.platform,
    g.status,
    g.allow_batch_image_generation,
    g.rate_multiplier::text AS rate_multiplier,
    g.image_rate_independent,
    g.image_rate_multiplier::text AS image_rate_multiplier,
    g.image_price_1k::text AS image_price_1k,
    g.image_price_2k::text AS image_price_2k,
    g.image_price_4k::text AS image_price_4k,
    g.batch_image_discount_multiplier::text AS discount_multiplier,
    g.batch_image_hold_multiplier::text AS hold_multiplier,
    user_rate.rate_multiplier::text AS user_rate_multiplier
FROM groups g
LEFT JOIN user_group_rate_multipliers user_rate
  ON user_rate.group_id = g.id AND user_rate.user_id = $2
WHERE g.id = $1 AND g.deleted_at IS NULL
LIMIT 1
",
        )
        .bind(group_id)
        .bind(owner.user_id)
        .fetch_optional(&self.inner.pool)
        .await?
        .ok_or_else(|| {
            BatchError::forbidden(
                "BATCH_IMAGE_GROUP_DISABLED",
                "batch image API is disabled for this group",
            )
        })?;
        let config = GroupBatchConfig::from_row(&row)?;
        if config.status != "active"
            || config.platform != "gemini"
            || !config.allow_batch_image_generation
        {
            return Err(BatchError::forbidden(
                "BATCH_IMAGE_GROUP_DISABLED",
                "batch image API is disabled for this group",
            ));
        }
        Ok(Some(config))
    }

    async fn select_account(
        &self,
        owner: &Owner,
        model: &str,
    ) -> Result<AccountSelection, BatchError> {
        let accounts = self
            .inner
            .repository
            .list_schedulable_accounts("gemini", owner.group_id, now_unix_seconds() * 1_000)
            .await?;
        for account in accounts {
            if account.proxy_id.is_some() {
                continue;
            }
            let Some(api_key) = provider_api_key(&account) else {
                continue;
            };
            let Some(upstream_model) = map_account_model(&account, model) else {
                continue;
            };
            return Ok(AccountSelection {
                base_url: provider_base_url(&account),
                account,
                api_key,
                upstream_model,
            });
        }
        Err(BatchError::upstream(
            "BATCH_IMAGE_NO_ACCOUNT_AVAILABLE",
            "no compatible batch image account is available",
        ))
    }

    async fn pricing(
        &self,
        owner: &Owner,
        request: &NormalizedRequest,
        account: &AccountRecord,
    ) -> Result<PricingSnapshot, BatchError> {
        let group = self.ensure_group_enabled(owner).await?;
        let base = group
            .as_ref()
            .and_then(|group| group.image_price(&request.image_size))
            .or_else(|| bundled_image_unit_price(&request.model))
            .ok_or_else(|| {
                BatchError::bad_request(
                    "BATCH_IMAGE_SETTLEMENT_PRICING_MISSING",
                    "batch image settlement pricing is missing",
                )
            })?;
        let group_multiplier = group
            .as_ref()
            .map_or(Ok(Decimal::ONE), GroupBatchConfig::effective_multiplier)?;
        let account_multiplier = decimal(&account.rate_multiplier, "account rate multiplier")?;
        let discount = group.as_ref().map_or_else(
            || decimal(DEFAULT_DISCOUNT, "batch discount"),
            GroupBatchConfig::discount,
        )?;
        let configured_hold = group.as_ref().map_or_else(
            || decimal(DEFAULT_HOLD_MULTIPLIER, "batch hold multiplier"),
            GroupBatchConfig::hold,
        )?;
        let hold_multiplier = configured_hold.max(discount);
        for (name, value) in [
            ("base unit price", base),
            ("group multiplier", group_multiplier),
            ("account multiplier", account_multiplier),
            ("discount multiplier", discount),
            ("hold multiplier", hold_multiplier),
        ] {
            if value.is_negative() {
                return Err(BatchError::internal(
                    "BATCH_IMAGE_SETTLEMENT_PRICING_MISSING",
                    format!("invalid {name}"),
                ));
            }
        }
        let standard = base
            .checked_mul(group_multiplier)?
            .checked_mul(account_multiplier)?;
        let billable_unit_price = standard.checked_mul(discount)?;
        let hold_unit_price = standard.checked_mul(hold_multiplier)?;
        let count = u64::try_from(request.items.len()).unwrap_or(u64::MAX);
        Ok(PricingSnapshot {
            base_unit_price: base,
            group_multiplier,
            account_multiplier,
            discount_multiplier: discount,
            hold_multiplier,
            billable_unit_price,
            hold_unit_price,
            estimated_cost: billable_unit_price.checked_mul_u64(count)?,
            hold_amount: hold_unit_price.checked_mul_u64(count)?,
        })
    }

    async fn load_by_idempotency(
        &self,
        owner: &Owner,
        key: &str,
    ) -> Result<Option<BatchJob>, BatchError> {
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE user_id = $1 AND api_key_id = $2 AND idempotency_key = $3 ORDER BY id DESC LIMIT 1"
        );
        sqlx::query(&sql)
            .bind(owner.user_id)
            .bind(owner.api_key_id)
            .bind(key)
            .fetch_optional(&self.inner.pool)
            .await?
            .as_ref()
            .map(BatchJob::from_row)
            .transpose()
    }

    async fn load_job_for_owner(
        &self,
        owner: &Owner,
        batch_id: &str,
    ) -> Result<BatchJob, BatchError> {
        validate_batch_id(batch_id)?;
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE batch_id = $1 AND user_id = $2 AND api_key_id = $3 AND user_deleted_at IS NULL LIMIT 1"
        );
        let row = sqlx::query(&sql)
            .bind(batch_id)
            .bind(owner.user_id)
            .bind(owner.api_key_id)
            .fetch_optional(&self.inner.pool)
            .await?
            .ok_or_else(BatchError::job_not_found)?;
        BatchJob::from_row(&row)
    }

    async fn load_job(&self, batch_id: &str) -> Result<BatchJob, BatchError> {
        let sql = format!("SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE batch_id = $1 LIMIT 1");
        let row = sqlx::query(&sql)
            .bind(batch_id)
            .fetch_optional(&self.inner.pool)
            .await?
            .ok_or_else(BatchError::job_not_found)?;
        BatchJob::from_row(&row)
    }

    async fn completed_job(&self, owner: &Owner, batch_id: &str) -> Result<BatchJob, BatchError> {
        let job = self.load_job_for_owner(owner, batch_id).await?;
        if job.output_deleted {
            return Err(BatchError::new(
                StatusCode::GONE,
                "BATCH_IMAGE_OUTPUT_DELETED",
                "batch image output has been deleted",
            ));
        }
        if job.status != "completed" {
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_NOT_READY",
                "batch image job is not completed",
            ));
        }
        Ok(job)
    }

    async fn load_account_for_job(&self, job: &BatchJob) -> Result<AccountRecord, BatchError> {
        let account_id = job.account_id.ok_or_else(|| {
            BatchError::internal(
                "BATCH_IMAGE_MISSING_ACCOUNT_ID",
                "batch image account id is missing",
            )
        })?;
        let account = self
            .inner
            .repository
            .find_account_by_id(account_id)
            .await?
            .ok_or_else(|| {
                BatchError::upstream(
                    "BATCH_IMAGE_PROVIDER_UNSUPPORTED_ACCOUNT",
                    "batch image provider account is unavailable",
                )
            })?;
        if account.proxy_id.is_some() {
            return Err(BatchError::upstream(
                "BATCH_IMAGE_PROVIDER_PROXY_UNSUPPORTED",
                "proxied accounts are not available for batch image generation",
            ));
        }
        Ok(account)
    }

    async fn mark_submitted(
        &self,
        batch_id: &str,
        provider: &ProviderBatch,
    ) -> Result<(), BatchError> {
        let result = sqlx::query(
            r"
UPDATE batch_image_jobs
SET status = 'submitted',
    provider_job_name = $2,
    provider_input_ref = $3,
    submitted_at = NOW(),
    updated_at = NOW(),
    version = version + 1
WHERE batch_id = $1 AND status IN ('created', 'uploading')
",
        )
        .bind(batch_id)
        .bind(&provider.name)
        .bind(&provider.input_ref)
        .execute(&self.inner.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_INVALID_TRANSITION",
                "batch image job changed while submitting",
            ));
        }
        self.append_event(
            batch_id,
            "provider_submitted",
            json!({
                "provider": "gemini_api",
                "state": provider.state,
            }),
        )
        .await;
        Ok(())
    }

    async fn reconcile_submit_persistence_failure(
        &self,
        batch_id: &str,
        error: &BatchError,
    ) -> Result<bool, BatchError> {
        let mut transaction = self.inner.pool.begin().await?;
        let job = load_job_for_update(&mut transaction, batch_id).await?;
        if !matches!(job.status.as_str(), "created" | "uploading") {
            let cleanup = matches!(job.status.as_str(), "failed" | "cancelled");
            transaction.rollback().await?;
            return Ok(cleanup);
        }
        release_hold(&mut transaction, job.user_id, &job.hold_amount).await?;
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET status = 'failed',
    finished_at = NOW(),
    updated_at = NOW(),
    last_error_code = $2,
    last_error_message = $3,
    version = version + 1
WHERE batch_id = $1 AND status IN ('created', 'uploading')
",
        )
        .bind(batch_id)
        .bind(&error.code)
        .bind(sanitize_public_error(&error.message))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
UPDATE batch_image_items
SET status = 'failed',
    error_code = $2,
    error_message = $3,
    indexed_at = NOW()
WHERE job_id = $1 AND status = 'pending'
",
        )
        .bind(batch_id)
        .bind(&error.code)
        .bind(sanitize_public_error(&error.message))
        .execute(&mut *transaction)
        .await?;
        insert_billing_dedup(
            &mut transaction,
            &format!("batch_image_release:{batch_id}"),
            job.api_key_id.unwrap_or_default(),
            job.request_hash.as_deref().unwrap_or_default(),
        )
        .await?;
        transaction.commit().await?;
        self.invalidate_auth_cache();
        Ok(true)
    }

    async fn cleanup_orphan_submission(
        &self,
        selection: &AccountSelection,
        provider: &ProviderBatch,
    ) {
        if let Err(error) = self
            .inner
            .provider
            .cancel(&selection.base_url, &selection.api_key, &provider.name)
            .await
        {
            tracing::warn!(
                provider_job_name = provider.name,
                error = %error,
                "cancel orphaned batch image provider job"
            );
        }
        if let Err(error) = self
            .inner
            .provider
            .delete_file(&selection.base_url, &selection.api_key, &provider.input_ref)
            .await
        {
            tracing::warn!(
                provider_input_ref = provider.input_ref,
                error = %error,
                "delete orphaned batch image provider input"
            );
        }
    }

    async fn fail_unsubmitted(
        &self,
        batch_id: &str,
        user_id: i64,
        hold_amount: &Decimal,
        error: &provider::ProviderError,
    ) -> Result<(), BatchError> {
        let mut transaction = self.inner.pool.begin().await?;
        let result = sqlx::query(
            r"
UPDATE users
SET balance = balance + $1::numeric,
    frozen_balance = frozen_balance - $1::numeric,
    updated_at = NOW()
WHERE id = $2 AND frozen_balance >= $1::numeric
",
        )
        .bind(hold_amount.to_string())
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        if !hold_amount.is_zero() && result.rows_affected() != 1 {
            transaction.rollback().await?;
            return Err(BatchError::internal(
                "BATCH_IMAGE_BILLING_HOLD_FAILED",
                "failed to release batch image balance hold",
            ));
        }
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET status = 'failed',
    user_deleted_at = NOW(),
    finished_at = NOW(),
    updated_at = NOW(),
    last_error_code = $2,
    last_error_message = $3,
    version = version + 1
WHERE batch_id = $1 AND status IN ('created', 'uploading')
",
        )
        .bind(batch_id)
        .bind(error.code())
        .bind(sanitize_public_error(error.message()))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.invalidate_auth_cache();
        Ok(())
    }

    async fn download_provider_output(&self, job: &BatchJob) -> Result<Vec<u8>, BatchError> {
        let output_ref = job.provider_output_ref.as_deref().ok_or_else(|| {
            BatchError::internal(
                "BATCH_IMAGE_RESULT_MISSING",
                "batch image provider output is missing",
            )
        })?;
        let account = self.load_account_for_job(job).await?;
        let base_url = provider_base_url(&account);
        let api_key = provider_api_key(&account).ok_or_else(|| {
            BatchError::upstream(
                "BATCH_IMAGE_PROVIDER_MISSING_API_KEY",
                "batch image provider account has no API key",
            )
        })?;
        self.inner
            .provider
            .download_file(&base_url, &api_key, output_ref, MAX_PROVIDER_OUTPUT_BYTES)
            .await
            .map_err(|error| error.public_download_error())
    }

    async fn mark_downloaded(&self, batch_id: &str) {
        if let Err(error) = sqlx::query(
            "UPDATE batch_image_jobs SET downloaded_at = COALESCE(downloaded_at, NOW()), updated_at = NOW() WHERE batch_id = $1",
        )
        .bind(batch_id)
        .execute(&self.inner.pool)
        .await
        {
            tracing::warn!(batch_id, error = %error, "mark batch image downloaded");
        }
    }

    async fn append_event(&self, batch_id: &str, event_type: &str, payload: Value) {
        if let Err(error) = sqlx::query(
            "INSERT INTO batch_image_events (job_id, event_type, payload) VALUES ($1, $2, $3::jsonb)",
        )
        .bind(batch_id)
        .bind(event_type)
        .bind(payload.to_string())
        .execute(&self.inner.pool)
        .await
        {
            tracing::warn!(batch_id, event_type, error = %error, "append batch image event");
        }
    }

    fn invalidate_auth_cache(&self) {
        if let Some(gateway) = &self.inner.gateway {
            gateway.invalidate_all_auth_cache();
        }
    }

    async fn worker_loop(&self, cancellation: CancellationToken) {
        let mut interval = tokio::time::interval(WORKER_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return,
                _ = interval.tick() => {
                    if let Err(error) = self.process_active_jobs().await {
                        tracing::error!(error = %error, "batch image worker scan failed");
                    }
                    if let Err(error) = self.cleanup_expired_outputs().await {
                        tracing::error!(error = %error, "batch image output cleanup scan failed");
                    }
                }
            }
        }
    }

    async fn cleanup_expired_outputs(&self) -> Result<(), BatchError> {
        let rows = sqlx::query(
            r"
WITH due AS (
    SELECT id
    FROM batch_image_jobs
    WHERE output_expires_at <= NOW()
      AND output_deleted_at IS NULL
      AND status IN ('completed', 'failed', 'cancelled')
    ORDER BY output_expires_at, id
    LIMIT 20
    FOR UPDATE SKIP LOCKED
)
UPDATE batch_image_jobs AS jobs
SET output_expires_at = NOW() + INTERVAL '5 minutes',
    updated_at = NOW()
FROM due
WHERE jobs.id = due.id
RETURNING jobs.batch_id
",
        )
        .fetch_all(&self.inner.pool)
        .await?;
        for row in rows {
            let batch_id: String = row.try_get("batch_id")?;
            if let Err(error) = self.cleanup_expired_output(&batch_id).await {
                tracing::warn!(batch_id, error = %error, "delete expired batch image output");
                let message = error.to_string();
                if let Err(update_error) = sqlx::query(
                    r"
UPDATE batch_image_jobs
SET output_expires_at = NOW() + INTERVAL '15 minutes',
    last_error_code = 'OUTPUT_CLEANUP_FAILED',
    last_error_message = $2,
    updated_at = NOW()
WHERE batch_id = $1 AND output_deleted_at IS NULL
",
                )
                .bind(&batch_id)
                .bind(&message)
                .execute(&self.inner.pool)
                .await
                {
                    tracing::warn!(batch_id, error = %update_error, "record batch image output cleanup failure");
                }
                self.append_event(
                    &batch_id,
                    "output_cleanup_failed",
                    json!({ "reason": "expired", "error": message }),
                )
                .await;
            }
        }
        Ok(())
    }

    async fn cleanup_expired_output(&self, batch_id: &str) -> Result<(), BatchError> {
        let job = self.load_job(batch_id).await?;
        if job.output_deleted {
            return Ok(());
        }
        self.append_event(
            batch_id,
            "output_cleanup_started",
            json!({ "reason": "expired" }),
        )
        .await;
        if let Some(output_ref) = job.provider_output_ref.as_deref() {
            let account = self.load_account_for_job(&job).await?;
            let api_key = provider_api_key(&account).ok_or_else(|| {
                BatchError::upstream(
                    "BATCH_IMAGE_PROVIDER_MISSING_API_KEY",
                    "batch image provider account has no API key",
                )
            })?;
            self.inner
                .provider
                .delete_file(&provider_base_url(&account), &api_key, output_ref)
                .await
                .map_err(|error| error.public_cleanup_error())?;
        }
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET output_deleted_at = COALESCE(output_deleted_at, NOW()),
    output_expires_at = NULL,
    status = 'output_deleted',
    last_error_code = NULL,
    last_error_message = NULL,
    updated_at = NOW()
WHERE batch_id = $1 AND output_deleted_at IS NULL
",
        )
        .bind(batch_id)
        .execute(&self.inner.pool)
        .await?;
        self.append_event(
            batch_id,
            "output_cleanup_completed",
            json!({ "reason": "expired" }),
        )
        .await;
        Ok(())
    }

    async fn process_active_jobs(&self) -> Result<(), BatchError> {
        self.recover_stale_uploads().await?;
        let rows = sqlx::query(
            r"
SELECT batch_id
FROM batch_image_jobs
WHERE status IN ('submitted', 'running')
  AND provider_job_name IS NOT NULL
ORDER BY updated_at, id
LIMIT 20
",
        )
        .fetch_all(&self.inner.pool)
        .await?;
        for row in rows {
            let batch_id: String = row.try_get("batch_id")?;
            if let Err(error) = self.poll_job(&batch_id).await {
                tracing::warn!(batch_id, error = %error, "poll batch image provider job");
                sqlx::query(
                    r"
UPDATE batch_image_jobs
SET retry_count = retry_count + 1,
    last_error_code = 'PROVIDER_POLL_FAILED',
    last_error_message = $2,
    updated_at = NOW()
WHERE batch_id = $1 AND status IN ('submitted', 'running')
",
                )
                .bind(&batch_id)
                .bind(sanitize_public_error(&error.to_string()))
                .execute(&self.inner.pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn recover_stale_uploads(&self) -> Result<(), BatchError> {
        let sql = format!(
            "SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE status IN ('created', 'uploading') AND provider_job_name IS NULL AND updated_at < NOW() - INTERVAL '10 minutes' ORDER BY updated_at LIMIT 20"
        );
        let rows = sqlx::query(&sql).fetch_all(&self.inner.pool).await?;
        for row in rows {
            let job = BatchJob::from_row(&row)?;
            self.finish_without_charge(
                &job,
                "failed",
                "STALE_UNSUBMITTED_JOB",
                "batch image submission did not complete",
            )
            .await?;
        }
        Ok(())
    }

    async fn poll_job(&self, batch_id: &str) -> Result<(), BatchError> {
        let job = self.load_job(batch_id).await?;
        if job.is_terminal() {
            return Ok(());
        }
        let provider_job_name = job.provider_job_name.as_deref().ok_or_else(|| {
            BatchError::internal(
                "BATCH_IMAGE_MISSING_PROVIDER_JOB_NAME",
                "batch image provider job name is missing",
            )
        })?;
        let account = self.load_account_for_job(&job).await?;
        let base_url = provider_base_url(&account);
        let api_key = provider_api_key(&account).ok_or_else(|| {
            BatchError::upstream(
                "BATCH_IMAGE_PROVIDER_MISSING_API_KEY",
                "batch image provider account has no API key",
            )
        })?;
        let state = self
            .inner
            .provider
            .get_batch(&base_url, &api_key, provider_job_name)
            .await
            .map_err(|error| error.public_poll_error())?;
        match state.state {
            ProviderState::Queued => Ok(()),
            ProviderState::Running => {
                sqlx::query(
                    r"
UPDATE batch_image_jobs
SET status = 'running', started_at = COALESCE(started_at, NOW()), updated_at = NOW()
WHERE batch_id = $1 AND status IN ('submitted', 'running')
",
                )
                .bind(batch_id)
                .execute(&self.inner.pool)
                .await?;
                Ok(())
            }
            ProviderState::Succeeded => {
                let output_ref = state.output_ref.ok_or_else(|| {
                    BatchError::upstream(
                        "GEMINI_RESULT_FILE_MISSING",
                        "Gemini batch succeeded without a result file reference",
                    )
                })?;
                sqlx::query(
                    "UPDATE batch_image_jobs SET provider_output_ref = $2, updated_at = NOW() WHERE batch_id = $1",
                )
                .bind(batch_id)
                .bind(&output_ref)
                .execute(&self.inner.pool)
                .await?;
                let output = self
                    .inner
                    .provider
                    .download_file(&base_url, &api_key, &output_ref, MAX_PROVIDER_OUTPUT_BYTES)
                    .await
                    .map_err(|error| error.public_download_error())?;
                self.index_and_settle(&job, &output_ref, &output).await
            }
            ProviderState::Failed => {
                self.finish_without_charge(
                    &job,
                    "failed",
                    state.error_code.as_deref().unwrap_or("GEMINI_BATCH_FAILED"),
                    state
                        .error_message
                        .as_deref()
                        .unwrap_or("Gemini batch failed"),
                )
                .await
            }
            ProviderState::Cancelled => {
                self.finish_without_charge(
                    &job,
                    "cancelled",
                    "GEMINI_BATCH_CANCELLED",
                    "Gemini batch was cancelled",
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn index_and_settle(
        &self,
        job: &BatchJob,
        output_ref: &str,
        output: &[u8],
    ) -> Result<(), BatchError> {
        let parsed = parse_provider_output_with_offsets(output)?;
        let mut transaction = self.inner.pool.begin().await?;
        let locked = load_job_for_update(&mut transaction, &job.batch_id).await?;
        if locked.is_terminal() {
            transaction.rollback().await?;
            return Ok(());
        }
        if !matches!(locked.status.as_str(), "submitted" | "running") {
            transaction.rollback().await?;
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_INDEX_STATE_CONFLICT",
                "batch image job is no longer ready for indexing",
            ));
        }
        sqlx::query("UPDATE batch_image_jobs SET status = 'indexing', updated_at = NOW() WHERE batch_id = $1")
            .bind(&job.batch_id)
            .execute(&mut *transaction)
            .await?;

        let existing = sqlx::query("SELECT custom_id FROM batch_image_items WHERE job_id = $1")
            .bind(&job.batch_id)
            .fetch_all(&mut *transaction)
            .await?;
        let expected = existing
            .iter()
            .map(|row| row.try_get::<String, _>("custom_id"))
            .collect::<Result<HashSet<_>, _>>()?;
        let mut seen = HashSet::new();
        for item in parsed {
            if !expected.contains(&item.custom_id) || !seen.insert(item.custom_id.clone()) {
                continue;
            }
            let (status, mime_type, extension, image_count, error_code, error_message) =
                if item.images.is_empty() {
                    (
                        "failed",
                        None,
                        None,
                        0_i32,
                        Some(item.error_code.as_deref().unwrap_or("EMPTY_IMAGE_OUTPUT")),
                        Some(
                            item.error_message
                                .as_deref()
                                .unwrap_or("provider response contained no image output"),
                        ),
                    )
                } else {
                    let first = &item.images[0];
                    (
                        "success",
                        Some(first.mime_type.as_str()),
                        Some(first.extension()),
                        i32::try_from(item.images.len()).unwrap_or(i32::MAX),
                        None,
                        None,
                    )
                };
            sqlx::query(
                r"
UPDATE batch_image_items
SET status = $3,
    provider_source_object = $4,
    source_line_number = $5,
    source_byte_offset = $6,
    source_byte_length = $7,
    mime_type = $8,
    file_extension = $9,
    image_count = $10,
    error_code = $11,
    error_message = $12,
    billed_amount = CASE WHEN $3 = 'success' THEN $13::numeric ELSE 0 END,
    indexed_at = NOW()
WHERE job_id = $1 AND custom_id = $2
",
            )
            .bind(&job.batch_id)
            .bind(&item.custom_id)
            .bind(status)
            .bind(output_ref)
            .bind(i32::try_from(item.line_number).unwrap_or(i32::MAX))
            .bind(i64::try_from(item.offset).unwrap_or(i64::MAX))
            .bind(i64::try_from(item.length).unwrap_or(i64::MAX))
            .bind(mime_type)
            .bind(extension)
            .bind(image_count)
            .bind(error_code)
            .bind(error_message.map(sanitize_public_error))
            .bind(locked.billable_unit_price.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            r"
UPDATE batch_image_items
SET status = 'failed',
    error_code = 'RESULT_MISSING',
    error_message = 'provider result was not found for item',
    indexed_at = NOW()
WHERE job_id = $1 AND status = 'pending'
",
        )
        .bind(&job.batch_id)
        .execute(&mut *transaction)
        .await?;
        let counts = sqlx::query(
            r"
SELECT
    COUNT(*) FILTER (WHERE status = 'success')::bigint AS success_count,
    COUNT(*) FILTER (WHERE status = 'failed')::bigint AS fail_count
FROM batch_image_items
WHERE job_id = $1
",
        )
        .bind(&job.batch_id)
        .fetch_one(&mut *transaction)
        .await?;
        let success_count: i64 = counts.try_get("success_count")?;
        let fail_count: i64 = counts.try_get("fail_count")?;
        let actual_cost = locked
            .billable_unit_price
            .checked_mul_u64(u64::try_from(success_count).unwrap_or(u64::MAX))?;
        if actual_cost > locked.hold_amount {
            transaction.rollback().await?;
            return Err(BatchError::new(
                StatusCode::CONFLICT,
                "BATCH_IMAGE_SETTLEMENT_COST_EXCEEDS_HOLD",
                "batch image settlement cost exceeds held balance",
            ));
        }
        capture_hold(
            &mut transaction,
            locked.user_id,
            &locked.hold_amount,
            &actual_cost,
        )
        .await?;
        let manifest_hash =
            settlement_manifest_hash(&locked, output_ref, success_count, fail_count);
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET status = 'completed',
    provider_output_ref = $2,
    success_count = $3,
    fail_count = $4,
    actual_cost = $5::numeric,
    manifest_hash = $6,
    finished_at = NOW(),
    settled_at = NOW(),
    output_expires_at = NOW() + INTERVAL '72 hours',
    updated_at = NOW(),
    last_error_code = NULL,
    last_error_message = NULL,
    version = version + 1
WHERE batch_id = $1
",
        )
        .bind(&job.batch_id)
        .bind(output_ref)
        .bind(i32::try_from(success_count).unwrap_or(i32::MAX))
        .bind(i32::try_from(fail_count).unwrap_or(i32::MAX))
        .bind(actual_cost.to_string())
        .bind(&manifest_hash)
        .execute(&mut *transaction)
        .await?;
        insert_billing_dedup(
            &mut transaction,
            &format!("batch_image_capture:{}", job.batch_id),
            locked.api_key_id.unwrap_or_default(),
            &manifest_hash,
        )
        .await?;
        transaction.commit().await?;
        self.invalidate_auth_cache();
        self.append_event(
            &job.batch_id,
            "job_completed",
            json!({
                "success_count": success_count,
                "fail_count": fail_count,
                "actual_cost": actual_cost.to_string(),
            }),
        )
        .await;
        self.cleanup_provider_input(job).await;
        Ok(())
    }

    async fn finish_without_charge(
        &self,
        job: &BatchJob,
        status: &str,
        error_code: &str,
        error_message: &str,
    ) -> Result<(), BatchError> {
        let mut transaction = self.inner.pool.begin().await?;
        let locked = load_job_for_update(&mut transaction, &job.batch_id).await?;
        if locked.is_terminal() {
            transaction.rollback().await?;
            return Ok(());
        }
        release_hold(&mut transaction, locked.user_id, &locked.hold_amount).await?;
        sqlx::query(
            r"
UPDATE batch_image_jobs
SET status = $2,
    cancelled_count = CASE WHEN $2 = 'cancelled' THEN item_count ELSE cancelled_count END,
    finished_at = NOW(),
    updated_at = NOW(),
    last_error_code = $3,
    last_error_message = $4,
    version = version + 1
WHERE batch_id = $1
",
        )
        .bind(&job.batch_id)
        .bind(status)
        .bind(error_code)
        .bind(sanitize_public_error(error_message))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r"
UPDATE batch_image_items
SET status = CASE WHEN $2 = 'cancelled' THEN 'cancelled' ELSE 'failed' END,
    error_code = $3,
    error_message = $4,
    indexed_at = NOW()
WHERE job_id = $1 AND status = 'pending'
",
        )
        .bind(&job.batch_id)
        .bind(status)
        .bind(error_code)
        .bind(sanitize_public_error(error_message))
        .execute(&mut *transaction)
        .await?;
        insert_billing_dedup(
            &mut transaction,
            &format!("batch_image_release:{}", job.batch_id),
            locked.api_key_id.unwrap_or_default(),
            locked.request_hash.as_deref().unwrap_or_default(),
        )
        .await?;
        transaction.commit().await?;
        self.invalidate_auth_cache();
        self.append_event(
            &job.batch_id,
            "job_finished",
            json!({
                "status": status,
                "error_code": error_code,
            }),
        )
        .await;
        self.cleanup_provider_input(job).await;
        Ok(())
    }

    async fn cleanup_provider_input(&self, job: &BatchJob) {
        let Some(input_ref) = job.provider_input_ref.as_deref() else {
            return;
        };
        let account = match self.load_account_for_job(job).await {
            Ok(account) => account,
            Err(error) => {
                tracing::warn!(
                    batch_id = job.batch_id,
                    error = %error,
                    "load account for batch image input cleanup"
                );
                return;
            }
        };
        let Some(api_key) = provider_api_key(&account) else {
            tracing::warn!(
                batch_id = job.batch_id,
                "batch image input cleanup has no provider API key"
            );
            return;
        };
        if let Err(error) = self
            .inner
            .provider
            .delete_file(&provider_base_url(&account), &api_key, input_ref)
            .await
        {
            tracing::warn!(
                batch_id = job.batch_id,
                error = %error,
                "delete batch image provider input"
            );
            return;
        }
        if let Err(error) = sqlx::query(
            "UPDATE batch_image_jobs SET input_deleted_at = COALESCE(input_deleted_at, NOW()), updated_at = NOW() WHERE batch_id = $1",
        )
        .bind(&job.batch_id)
        .execute(&self.inner.pool)
        .await
        {
            tracing::warn!(
                batch_id = job.batch_id,
                error = %error,
                "mark batch image provider input deleted"
            );
        }
    }
}

pub struct BatchImageWorker {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

impl BatchImageWorker {
    /// Stops the polling worker after the current provider operation finishes.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker task panicked or was aborted.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        self.cancellation.cancel();
        self.task.await
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)]
struct Owner {
    user_id: i64,
    api_key_id: i64,
    group_id: Option<i64>,
}

#[derive(Debug)]
enum BatchRoute {
    Submit,
    List,
    Models,
    Get(String),
    Items(String),
    ItemContent { batch_id: String, custom_id: String },
    Download(String),
    Cancel(String),
    Delete(String),
    DeleteOutputs(String),
}

impl BatchRoute {
    fn classify(method: &Method, path: &str) -> Result<Self, BatchError> {
        let path = path.trim_end_matches('/');
        if path == "/v1/images/batches" {
            return match *method {
                Method::POST => Ok(Self::Submit),
                Method::GET => Ok(Self::List),
                _ => Err(BatchError::method_not_allowed()),
            };
        }
        if path == "/v1/images/batches/models" {
            return (*method == Method::GET)
                .then_some(Self::Models)
                .ok_or_else(BatchError::method_not_allowed);
        }
        let remainder = path
            .strip_prefix("/v1/images/batches/")
            .ok_or_else(BatchError::job_not_found)?;
        let parts = remainder.split('/').collect::<Vec<_>>();
        let batch_id = parts.first().copied().unwrap_or_default();
        validate_batch_id(batch_id)?;
        match (method, parts.as_slice()) {
            (&Method::GET, [_]) => Ok(Self::Get(batch_id.to_owned())),
            (&Method::DELETE, [_]) => Ok(Self::Delete(batch_id.to_owned())),
            (&Method::GET, [_, "items"]) => Ok(Self::Items(batch_id.to_owned())),
            (&Method::GET, [_, "download"]) => Ok(Self::Download(batch_id.to_owned())),
            (&Method::POST, [_, "cancel"]) => Ok(Self::Cancel(batch_id.to_owned())),
            (&Method::DELETE, [_, "outputs"]) => Ok(Self::DeleteOutputs(batch_id.to_owned())),
            (&Method::GET, [_, "items", custom_id, "content"]) if valid_custom_id(custom_id) => {
                Ok(Self::ItemContent {
                    batch_id: batch_id.to_owned(),
                    custom_id: (*custom_id).to_owned(),
                })
            }
            _ => Err(BatchError::job_not_found()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SubmitRequest {
    model: String,
    #[serde(default)]
    task_name: String,
    #[serde(default)]
    parent_batch_id: String,
    #[serde(default)]
    provider: String,
    items: Vec<SubmitItem>,
    #[serde(default)]
    response_mime_type: String,
    #[serde(default)]
    aspect_ratio: String,
    #[serde(default)]
    image_size: String,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SubmitItem {
    #[serde(default)]
    custom_id: String,
    prompt: String,
    #[serde(default)]
    output_count: usize,
    #[serde(default)]
    reference_images: Vec<ReferenceInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReferenceInput {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "type")]
    kind: String,
    mime_type: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    file_uri: String,
}

#[derive(Clone, Debug, Serialize)]
struct NormalizedRequest {
    model: String,
    task_name: String,
    parent_batch_id: Option<String>,
    provider: String,
    items: Vec<NormalizedItem>,
    response_mime_type: String,
    aspect_ratio: String,
    image_size: String,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
struct NormalizedItem {
    custom_id: String,
    prompt: String,
    reference_images: Vec<NormalizedReference>,
}

#[derive(Clone, Debug, Serialize)]
struct NormalizedReference {
    id: String,
    kind: String,
    mime_type: String,
    data: String,
    file_uri: String,
}

impl NormalizedRequest {
    #[allow(clippy::too_many_lines)]
    fn new(request: SubmitRequest) -> Result<Self, BatchError> {
        let model = request.model.trim().to_owned();
        if model.is_empty() || model.len() > 128 || model.contains('/') {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_INVALID_MODEL",
                "batch image model is required",
            ));
        }
        let provider = request.provider.trim();
        if !provider.is_empty() && provider != "gemini_api" {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_INVALID_PROVIDER",
                "only gemini_api batch image provider is supported",
            ));
        }
        if request.items.is_empty() || request.items.len() > MAX_ITEMS {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_INVALID_ITEMS",
                "batch image items are invalid",
            ));
        }
        let mut seen = HashSet::new();
        let mut items = Vec::new();
        let mut reference_bytes = 0_usize;
        for (index, item) in request.items.into_iter().enumerate() {
            let prompt = item.prompt.trim().to_owned();
            if prompt.is_empty() {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_INVALID_ITEMS",
                    "batch image prompt is required",
                ));
            }
            if prompt.chars().count() > MAX_PROMPT_CHARS {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_PROMPT_TOO_LONG",
                    "batch image prompt is too long",
                ));
            }
            let custom_id = if item.custom_id.trim().is_empty() {
                format!("item_{:06}", index + 1)
            } else {
                item.custom_id.trim().to_owned()
            };
            if !valid_custom_id(&custom_id) {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_INVALID_ITEMS",
                    "batch image custom id is invalid",
                ));
            }
            let output_count = item.output_count.max(1);
            if output_count > MAX_OUTPUTS_PER_ITEM || items.len() + output_count > MAX_ITEMS {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_TOO_MANY_OUTPUT_IMAGES",
                    "too many batch image output images",
                ));
            }
            let references = normalize_references(&model, item.reference_images)?;
            for reference in &references {
                if !reference.data.is_empty() {
                    let decoded = BASE64.decode(reference.data.as_bytes()).map_err(|_| {
                        BatchError::bad_request(
                            "BATCH_IMAGE_INVALID_REFERENCE_IMAGE",
                            "batch image reference image is invalid",
                        )
                    })?;
                    if decoded.len() > MAX_REFERENCE_BYTES {
                        return Err(BatchError::bad_request(
                            "BATCH_IMAGE_INVALID_REFERENCE_IMAGE",
                            "batch image reference image is too large",
                        ));
                    }
                    reference_bytes = reference_bytes
                        .checked_add(decoded.len().saturating_mul(output_count))
                        .ok_or_else(|| {
                            BatchError::bad_request(
                                "BATCH_IMAGE_REFERENCE_IMAGES_TOO_LARGE",
                                "batch image reference images are too large",
                            )
                        })?;
                }
            }
            if reference_bytes > MAX_REFERENCE_BYTES_PER_JOB {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_REFERENCE_IMAGES_TOO_LARGE",
                    "batch image reference images are too large",
                ));
            }
            for output_index in 0..output_count {
                let expanded_id = if output_count == 1 {
                    custom_id.clone()
                } else {
                    format!("{}_{:02}", custom_id, output_index + 1)
                };
                if !seen.insert(expanded_id.clone()) {
                    return Err(BatchError::bad_request(
                        "BATCH_IMAGE_DUPLICATE_CUSTOM_ID",
                        "batch image custom ids must be unique",
                    ));
                }
                items.push(NormalizedItem {
                    custom_id: expanded_id,
                    prompt: prompt.clone(),
                    reference_images: references.clone(),
                });
            }
        }
        let response_mime_type = match request.response_mime_type.trim() {
            "" => DEFAULT_RESPONSE_MIME.to_owned(),
            "image/png" | "image/jpeg" | "image/webp" => {
                request.response_mime_type.trim().to_owned()
            }
            _ => {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_INVALID_ITEMS",
                    "batch image response mime type is invalid",
                ));
            }
        };
        let image_size = match request.image_size.trim().to_ascii_uppercase().as_str() {
            "" => DEFAULT_IMAGE_SIZE.to_owned(),
            "1K" | "2K" | "4K" => request.image_size.trim().to_ascii_uppercase(),
            _ => {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_INVALID_ITEMS",
                    "batch image size is invalid",
                ));
            }
        };
        let task_name = request.task_name.trim().to_owned();
        if task_name.len() > 255 {
            return Err(BatchError::bad_request(
                "BATCH_IMAGE_INVALID_ITEMS",
                "batch image task name is too long",
            ));
        }
        let parent_batch_id = match request.parent_batch_id.trim() {
            "" => None,
            value => {
                validate_batch_id(value)?;
                Some(value.to_owned())
            }
        };
        let metadata = request
            .metadata
            .into_iter()
            .filter_map(|(key, value)| {
                let key = key.trim();
                if key.is_empty() || key.len() > 64 {
                    None
                } else {
                    Some((key.to_owned(), value.trim().chars().take(256).collect()))
                }
            })
            .take(20)
            .collect();
        Ok(Self {
            model,
            task_name,
            parent_batch_id,
            provider: "gemini_api".to_owned(),
            items,
            response_mime_type,
            aspect_ratio: request.aspect_ratio.trim().to_owned(),
            image_size,
            metadata,
        })
    }

    fn hash(&self) -> Result<String, BatchError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn gemini_jsonl(&self, _upstream_model: &str) -> Result<Vec<u8>, BatchError> {
        let mut output = Vec::new();
        for item in &self.items {
            let mut parts = vec![json!({ "text": item.prompt })];
            for reference in &item.reference_images {
                if reference.data.is_empty() {
                    parts.push(json!({
                        "fileData": {
                            "mimeType": reference.mime_type,
                            "fileUri": reference.file_uri,
                        }
                    }));
                } else {
                    parts.push(json!({
                        "inlineData": {
                            "mimeType": reference.mime_type,
                            "data": reference.data,
                        }
                    }));
                }
            }
            serde_json::to_writer(
                &mut output,
                &json!({
                    "key": item.custom_id,
                    "request": {
                        "contents": [{ "parts": parts }],
                        "generationConfig": {
                            "responseModalities": ["TEXT", "IMAGE"]
                        }
                    }
                }),
            )?;
            output.push(b'\n');
        }
        Ok(output)
    }
}

fn normalize_references(
    model: &str,
    references: Vec<ReferenceInput>,
) -> Result<Vec<NormalizedReference>, BatchError> {
    let lower = model.to_ascii_lowercase();
    let max_references = if lower.contains("pro-image") {
        14
    } else if lower.contains("flash-image") {
        3
    } else {
        0
    };
    if references.len() > max_references {
        return Err(BatchError::bad_request(
            "BATCH_IMAGE_TOO_MANY_REFERENCE_IMAGES",
            "too many batch image reference images for this model",
        ));
    }
    references
        .into_iter()
        .map(|reference| {
            let mime_type = match reference.mime_type.trim().to_ascii_lowercase().as_str() {
                "image/jpeg" | "image/jpg" => "image/jpeg",
                "image/png" => "image/png",
                "image/webp" => "image/webp",
                _ => {
                    return Err(BatchError::bad_request(
                        "BATCH_IMAGE_INVALID_REFERENCE_IMAGE",
                        "batch image reference image is invalid",
                    ));
                }
            };
            let data = reference.data.trim().to_owned();
            let file_uri = reference.file_uri.trim().to_owned();
            if data.is_empty() == file_uri.is_empty()
                || (!file_uri.is_empty() && !file_uri.starts_with("gs://"))
            {
                return Err(BatchError::bad_request(
                    "BATCH_IMAGE_INVALID_REFERENCE_IMAGE",
                    "batch image reference image is invalid",
                ));
            }
            Ok(NormalizedReference {
                id: reference.id.trim().chars().take(80).collect(),
                kind: reference.kind.trim().chars().take(40).collect(),
                mime_type: mime_type.to_owned(),
                data,
                file_uri,
            })
        })
        .collect()
}

struct AccountSelection {
    account: AccountRecord,
    base_url: String,
    api_key: String,
    upstream_model: String,
}

struct PricingSnapshot {
    base_unit_price: Decimal,
    group_multiplier: Decimal,
    account_multiplier: Decimal,
    discount_multiplier: Decimal,
    hold_multiplier: Decimal,
    billable_unit_price: Decimal,
    hold_unit_price: Decimal,
    estimated_cost: Decimal,
    hold_amount: Decimal,
}

struct GroupBatchConfig {
    platform: String,
    status: String,
    allow_batch_image_generation: bool,
    rate_multiplier: String,
    image_rate_independent: bool,
    image_rate_multiplier: String,
    image_price_1k: Option<String>,
    image_price_2k: Option<String>,
    image_price_4k: Option<String>,
    discount_multiplier: String,
    hold_multiplier: String,
    user_rate_multiplier: Option<String>,
}

impl GroupBatchConfig {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            platform: row.try_get("platform")?,
            status: row.try_get("status")?,
            allow_batch_image_generation: row.try_get("allow_batch_image_generation")?,
            rate_multiplier: row.try_get("rate_multiplier")?,
            image_rate_independent: row.try_get("image_rate_independent")?,
            image_rate_multiplier: row.try_get("image_rate_multiplier")?,
            image_price_1k: row.try_get("image_price_1k")?,
            image_price_2k: row.try_get("image_price_2k")?,
            image_price_4k: row.try_get("image_price_4k")?,
            discount_multiplier: row.try_get("discount_multiplier")?,
            hold_multiplier: row.try_get("hold_multiplier")?,
            user_rate_multiplier: row.try_get("user_rate_multiplier")?,
        })
    }

    fn image_price(&self, image_size: &str) -> Option<Decimal> {
        let value = match image_size {
            "1K" => self.image_price_1k.as_deref(),
            "4K" => self.image_price_4k.as_deref(),
            _ => self.image_price_2k.as_deref(),
        }?;
        Decimal::from_str(value).ok()
    }

    fn effective_multiplier(&self) -> Result<Decimal, BatchError> {
        if self.image_rate_independent {
            decimal(&self.image_rate_multiplier, "image rate multiplier")
        } else if let Some(value) = self.user_rate_multiplier.as_deref() {
            decimal(value, "user group rate multiplier")
        } else {
            decimal(&self.rate_multiplier, "group rate multiplier")
        }
    }

    fn discount(&self) -> Result<Decimal, BatchError> {
        decimal(&self.discount_multiplier, "batch discount multiplier")
    }

    fn hold(&self) -> Result<Decimal, BatchError> {
        decimal(&self.hold_multiplier, "batch hold multiplier")
    }
}

#[derive(Clone, Debug)]
struct BatchJob {
    batch_id: String,
    user_id: i64,
    api_key_id: Option<i64>,
    account_id: Option<i64>,
    provider: String,
    model: String,
    task_name: String,
    parent_batch_id: Option<String>,
    status: String,
    provider_job_name: Option<String>,
    provider_input_ref: Option<String>,
    provider_output_ref: Option<String>,
    item_count: i32,
    success_count: i32,
    fail_count: i32,
    estimated_cost: Decimal,
    hold_amount: Decimal,
    actual_cost: Option<Decimal>,
    billable_unit_price: Decimal,
    request_hash: Option<String>,
    output_deleted: bool,
    created_at: i64,
    submitted_at: Option<i64>,
    settled_at: Option<i64>,
    downloaded_at: Option<i64>,
    output_deleted_at: Option<i64>,
}

impl BatchJob {
    fn from_row(row: &PgRow) -> Result<Self, BatchError> {
        Ok(Self {
            batch_id: row.try_get("batch_id")?,
            user_id: row.try_get("user_id")?,
            api_key_id: row.try_get("api_key_id")?,
            account_id: row.try_get("account_id")?,
            provider: row.try_get("provider")?,
            model: row.try_get("model")?,
            task_name: row.try_get("task_name")?,
            parent_batch_id: row.try_get("parent_batch_id")?,
            status: row.try_get("status")?,
            provider_job_name: row.try_get("provider_job_name")?,
            provider_input_ref: row.try_get("provider_input_ref")?,
            provider_output_ref: row.try_get("provider_output_ref")?,
            item_count: row.try_get("item_count")?,
            success_count: row.try_get("success_count")?,
            fail_count: row.try_get("fail_count")?,
            estimated_cost: row_decimal(row, "estimated_cost")?,
            hold_amount: row
                .try_get::<Option<String>, _>("hold_amount")?
                .as_deref()
                .map_or(Ok(Decimal::ZERO), Decimal::from_str)?,
            actual_cost: row
                .try_get::<Option<String>, _>("actual_cost")?
                .as_deref()
                .map(Decimal::from_str)
                .transpose()?,
            billable_unit_price: row_decimal(row, "billable_unit_price")?,
            request_hash: row.try_get("request_hash")?,
            output_deleted: row.try_get("output_deleted")?,
            created_at: row.try_get("created_at")?,
            submitted_at: row.try_get("submitted_at")?,
            settled_at: row.try_get("settled_at")?,
            downloaded_at: row.try_get("downloaded_at")?,
            output_deleted_at: row.try_get("output_deleted_at")?,
        })
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            "completed" | "failed" | "cancelled" | "output_deleted"
        )
    }

    fn public_status(&self) -> &str {
        match self.status.as_str() {
            "created" | "uploading" | "submitted" => "queued",
            "indexing" => "processing_results",
            "settling" => "settling",
            value => value,
        }
    }

    fn public_value(&self) -> Value {
        json!({
            "id": self.batch_id,
            "object": "image.batch",
            "task_name": self.task_name,
            "parent_batch_id": self.parent_batch_id,
            "status": self.public_status(),
            "model": self.model,
            "provider": self.provider,
            "item_count": self.item_count,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "estimated_cost": decimal_value(self.estimated_cost),
            "hold_amount": decimal_value(self.hold_amount),
            "actual_cost": self.actual_cost.map(decimal_value),
            "created_at": self.created_at,
            "submitted_at": self.submitted_at,
            "settled_at": self.settled_at,
            "downloaded_at": self.downloaded_at,
            "output_deleted_at": self.output_deleted_at,
        })
    }
}

#[derive(Clone, Debug)]
struct OutputImage {
    mime_type: String,
    data: String,
}

impl OutputImage {
    fn extension(&self) -> &str {
        match self.mime_type.as_str() {
            "image/png" => "png",
            "image/jpeg" | "image/jpg" => "jpg",
            "image/webp" => "webp",
            "image/gif" => "gif",
            _ => "bin",
        }
    }
}

#[derive(Clone, Debug)]
struct OutputItem {
    custom_id: String,
    images: Vec<OutputImage>,
    error_code: Option<String>,
    error_message: Option<String>,
    line_number: usize,
    offset: usize,
    length: usize,
}

#[allow(clippy::too_many_arguments)]
async fn insert_job_and_hold(
    transaction: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    batch_id: &str,
    task_name: &str,
    request: &NormalizedRequest,
    selection: &AccountSelection,
    pricing: &PricingSnapshot,
    idempotency_key: &str,
    request_hash: &str,
) -> Result<(), BatchError> {
    if !pricing.hold_amount.is_zero() {
        let held = sqlx::query(
            r"
UPDATE users
SET balance = balance - $1::numeric,
    frozen_balance = COALESCE(frozen_balance, 0) + $1::numeric,
    updated_at = NOW()
WHERE id = $2 AND deleted_at IS NULL AND balance >= $1::numeric
",
        )
        .bind(pricing.hold_amount.to_string())
        .bind(owner.user_id)
        .execute(&mut **transaction)
        .await?;
        if held.rows_affected() != 1 {
            return Err(BatchError::new(
                StatusCode::PAYMENT_REQUIRED,
                "BATCH_IMAGE_INSUFFICIENT_BALANCE",
                "insufficient balance for batch image hold",
            ));
        }
    }
    sqlx::query(
        r"
INSERT INTO batch_image_jobs (
    batch_id, user_id, api_key_id, account_id, provider, model, task_name,
    parent_batch_id, status, item_count, estimated_cost, hold_amount,
    base_unit_price, group_rate_multiplier, account_rate_multiplier,
    batch_discount_multiplier, hold_multiplier, billable_unit_price,
    hold_unit_price, pricing_snapshot_version, currency, hold_id,
    idempotency_key, request_hash
) VALUES (
    $1, $2, $3, $4, 'gemini_api', $5, $6, $7, 'uploading', $8,
    $9::numeric, $10::numeric, $11::numeric, $12::numeric, $13::numeric,
    $14::numeric, $15::numeric, $16::numeric, $17::numeric, 1, 'USD', $18,
    NULLIF($19, ''), $20
)
",
    )
    .bind(batch_id)
    .bind(owner.user_id)
    .bind(owner.api_key_id)
    .bind(selection.account.id)
    .bind(&request.model)
    .bind(task_name)
    .bind(&request.parent_batch_id)
    .bind(i32::try_from(request.items.len()).unwrap_or(i32::MAX))
    .bind(pricing.estimated_cost.to_string())
    .bind(pricing.hold_amount.to_string())
    .bind(pricing.base_unit_price.to_string())
    .bind(pricing.group_multiplier.to_string())
    .bind(pricing.account_multiplier.to_string())
    .bind(pricing.discount_multiplier.to_string())
    .bind(pricing.hold_multiplier.to_string())
    .bind(pricing.billable_unit_price.to_string())
    .bind(pricing.hold_unit_price.to_string())
    .bind(format!("batch_image_hold:{batch_id}"))
    .bind(idempotency_key)
    .bind(request_hash)
    .execute(&mut **transaction)
    .await?;
    insert_billing_dedup(
        transaction,
        &format!("batch_image_hold:{batch_id}"),
        owner.api_key_id,
        request_hash,
    )
    .await?;
    Ok(())
}

async fn insert_pending_items(
    transaction: &mut Transaction<'_, Postgres>,
    batch_id: &str,
    request_hash: &str,
    items: &[NormalizedItem],
) -> Result<(), BatchError> {
    for item in items {
        let preview = item.prompt.chars().take(500).collect::<String>();
        sqlx::query(
            r"
INSERT INTO batch_image_items (
    job_id, custom_id, status, request_hash, prompt_preview
) VALUES ($1, $2, 'pending', $3, $4)
",
        )
        .bind(batch_id)
        .bind(&item.custom_id)
        .bind(request_hash)
        .bind(preview)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn load_by_idempotency_tx(
    transaction: &mut Transaction<'_, Postgres>,
    owner: &Owner,
    key: &str,
) -> Result<Option<BatchJob>, BatchError> {
    let sql = format!(
        "SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE user_id = $1 AND api_key_id = $2 AND idempotency_key = $3 ORDER BY id DESC LIMIT 1"
    );
    sqlx::query(&sql)
        .bind(owner.user_id)
        .bind(owner.api_key_id)
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await?
        .as_ref()
        .map(BatchJob::from_row)
        .transpose()
}

async fn load_job_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    batch_id: &str,
) -> Result<BatchJob, BatchError> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM batch_image_jobs WHERE batch_id = $1 FOR UPDATE");
    let row = sqlx::query(&sql)
        .bind(batch_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(BatchError::job_not_found)?;
    BatchJob::from_row(&row)
}

async fn capture_hold(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    hold: &Decimal,
    actual: &Decimal,
) -> Result<(), BatchError> {
    if hold.is_zero() && actual.is_zero() {
        return Ok(());
    }
    let result = sqlx::query(
        r"
UPDATE users
SET balance = balance + ($1::numeric - $2::numeric),
    frozen_balance = frozen_balance - $1::numeric,
    updated_at = NOW()
WHERE id = $3 AND deleted_at IS NULL AND frozen_balance >= $1::numeric
",
    )
    .bind(hold.to_string())
    .bind(actual.to_string())
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(BatchError::internal(
            "BATCH_IMAGE_SETTLEMENT_BILLING_FAILED",
            "batch image settlement billing failed",
        ));
    }
    Ok(())
}

async fn release_hold(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    hold: &Decimal,
) -> Result<(), BatchError> {
    if hold.is_zero() {
        return Ok(());
    }
    let result = sqlx::query(
        r"
UPDATE users
SET balance = balance + $1::numeric,
    frozen_balance = frozen_balance - $1::numeric,
    updated_at = NOW()
WHERE id = $2 AND deleted_at IS NULL AND frozen_balance >= $1::numeric
",
    )
    .bind(hold.to_string())
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(BatchError::internal(
            "BATCH_IMAGE_BILLING_HOLD_FAILED",
            "failed to release batch image balance hold",
        ));
    }
    Ok(())
}

async fn insert_billing_dedup(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: &str,
    api_key_id: i64,
    fingerprint: &str,
) -> Result<(), BatchError> {
    if api_key_id <= 0 {
        return Ok(());
    }
    let fingerprint = if fingerprint.len() <= 64 {
        fingerprint.to_owned()
    } else {
        hex::encode(Sha256::digest(fingerprint.as_bytes()))
    };
    sqlx::query(
        r"
INSERT INTO usage_billing_dedup (request_id, api_key_id, request_fingerprint)
VALUES ($1, $2, $3)
ON CONFLICT (request_id, api_key_id) DO NOTHING
",
    )
    .bind(request_id)
    .bind(api_key_id)
    .bind(fingerprint)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn public_item(row: &PgRow) -> Result<Value, BatchError> {
    let status: String = row.try_get("status")?;
    let public_status = match status.as_str() {
        "success" => "succeeded",
        "pending" => "pending",
        _ => "failed",
    };
    let error = if public_status == "failed" {
        let provider_source: Option<String> = row.try_get("provider_source_object")?;
        let code = row
            .try_get::<Option<String>, _>("error_code")?
            .unwrap_or_default();
        let source = if provider_source.is_some()
            || matches!(code.as_str(), "EMPTY_IMAGE_OUTPUT" | "PROVIDER_ITEM_FAILED")
        {
            "provider"
        } else if matches!(
            code.as_str(),
            "INDEX_OUTPUT_MISSING" | "INDEX_PARSE_FAILED" | "DUPLICATE_CUSTOM_ID_IN_OUTPUT"
        ) {
            "system"
        } else {
            ""
        };
        Some(json!({
            "code": code,
            "message": sanitize_public_error(
                row.try_get::<Option<String>, _>("error_message")?.as_deref().unwrap_or_default()
            ),
            "source": source,
        }))
    } else {
        None
    };
    Ok(json!({
        "custom_id": row.try_get::<String, _>("custom_id")?,
        "status": public_status,
        "prompt_preview": row.try_get::<Option<String>, _>("prompt_preview")?,
        "mime_type": row.try_get::<Option<String>, _>("mime_type")?,
        "file_extension": row.try_get::<Option<String>, _>("file_extension")?,
        "image_count": row.try_get::<i32, _>("image_count")?,
        "error": error,
    }))
}

fn parse_provider_output(output: &[u8]) -> Result<HashMap<String, OutputItem>, BatchError> {
    let mut map = HashMap::new();
    for item in parse_provider_output_with_offsets(output)? {
        map.entry(item.custom_id.clone()).or_insert(item);
    }
    Ok(map)
}

#[allow(clippy::too_many_lines)]
fn parse_provider_output_with_offsets(output: &[u8]) -> Result<Vec<OutputItem>, BatchError> {
    let mut items = Vec::new();
    let mut offset = 0_usize;
    for (line_number, raw) in output.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let length = raw.len();
        let line = raw
            .strip_suffix(b"\n")
            .unwrap_or(raw)
            .strip_suffix(b"\r")
            .unwrap_or(raw.strip_suffix(b"\n").unwrap_or(raw));
        if line.iter().all(u8::is_ascii_whitespace) {
            offset = offset.saturating_add(length);
            continue;
        }
        let value: Value = serde_json::from_slice(line).map_err(|_| {
            BatchError::upstream(
                "BATCH_IMAGE_INDEX_PARSE_FAILED",
                "batch image provider output parse failed",
            )
        })?;
        let custom_id = [
            value.get("key"),
            value.get("custom_id"),
            value.get("customId"),
            value.pointer("/request/key"),
        ]
        .into_iter()
        .flatten()
        .find_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BatchError::upstream(
                "BATCH_IMAGE_INDEX_PARSE_FAILED",
                "batch image provider output is missing custom id",
            )
        })?
        .to_owned();
        let mut images = Vec::new();
        for candidates in [
            value.pointer("/response/candidates"),
            value.get("candidates"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        {
            for candidate in candidates {
                let Some(parts) = candidate
                    .pointer("/content/parts")
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for part in parts {
                    let inline = part.get("inlineData").or_else(|| part.get("inline_data"));
                    let Some(inline) = inline else {
                        continue;
                    };
                    let data = inline
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let mime_type = inline
                        .get("mimeType")
                        .or_else(|| inline.get("mime_type"))
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !data.is_empty() && mime_type.starts_with("image/") {
                        images.push(OutputImage {
                            mime_type: mime_type.to_owned(),
                            data: data.to_owned(),
                        });
                    }
                }
            }
        }
        let provider_error = value
            .get("error")
            .or_else(|| value.pointer("/response/error"));
        let error_code = provider_error.and_then(|error| {
            error
                .get("status")
                .or_else(|| error.get("code"))
                .map(value_string)
        });
        let error_message = provider_error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .map(sanitize_public_error);
        items.push(OutputItem {
            custom_id,
            images,
            error_code,
            error_message,
            line_number: line_number + 1,
            offset,
            length,
        });
        offset = offset.saturating_add(length);
    }
    if items.is_empty() {
        return Err(BatchError::upstream(
            "BATCH_IMAGE_INDEX_NO_RESULT_LINES",
            "batch image provider output has no result lines",
        ));
    }
    Ok(items)
}

fn find_output_item(output: &[u8], custom_id: &str) -> Result<Option<OutputItem>, BatchError> {
    Ok(parse_provider_output_with_offsets(output)?
        .into_iter()
        .find(|item| item.custom_id == custom_id))
}

fn map_account_model(account: &AccountRecord, requested: &str) -> Option<String> {
    let Some(mapping) = account
        .credentials
        .get("model_mapping")
        .and_then(Value::as_object)
    else {
        return Some(requested.to_owned());
    };
    if mapping.is_empty() {
        return Some(requested.to_owned());
    }
    let mut best: Option<(&str, &str)> = None;
    for (pattern, target) in mapping {
        let target = target
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())?;
        let matched = pattern == requested
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| requested.starts_with(prefix));
        if matched && best.is_none_or(|(current, _)| pattern.len() > current.len()) {
            best = Some((pattern, target));
        }
    }
    best.map(|(_, target)| target.to_owned())
}

fn mapped_models(account: &AccountRecord) -> Vec<String> {
    account
        .credentials
        .get("model_mapping")
        .and_then(Value::as_object)
        .map(|mapping| {
            mapping
                .keys()
                .filter(|model| !model.contains(['*', '?']))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn provider_api_key(account: &AccountRecord) -> Option<String> {
    if !account.account_type.eq_ignore_ascii_case("apikey") {
        return None;
    }
    ["api_key", "key", "token"]
        .into_iter()
        .find_map(|key| {
            account
                .credentials
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_owned)
}

fn provider_base_url(account: &AccountRecord) -> String {
    account
        .credentials
        .get("base_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("https://generativelanguage.googleapis.com")
        .trim_end_matches('/')
        .to_owned()
}

fn bundled_image_unit_price(model: &str) -> Option<Decimal> {
    static CATALOG: OnceLock<Option<Value>> = OnceLock::new();
    let catalog = CATALOG
        .get_or_init(|| serde_json::from_str(MODEL_PRICES).ok())
        .as_ref()?;
    let pricing = catalog.get(model)?;
    ["output_cost_per_image", "default_per_request_price"]
        .into_iter()
        .find_map(|field| pricing.get(field))
        .map(value_string)
        .and_then(|value| Decimal::from_str(&value).ok())
}

fn default_models() -> [&'static str; 7] {
    [
        "gemini-2.0-flash-exp-image-generation",
        "gemini-2.5-flash-image",
        "gemini-3-pro-image",
        "gemini-3-pro-image-preview",
        "gemini-3.1-flash-image",
        "gemini-3.1-flash-image-preview",
        "gemini-3.1-flash-lite-image",
    ]
}

fn settlement_manifest_hash(
    job: &BatchJob,
    output_ref: &str,
    success_count: i64,
    fail_count: i64,
) -> String {
    let parts = [
        job.batch_id.as_str(),
        job.provider.as_str(),
        job.model.as_str(),
        job.provider_job_name.as_deref().unwrap_or_default(),
        output_ref,
        &success_count.to_string(),
        &fail_count.to_string(),
        &job.item_count.to_string(),
    ];
    hex::encode(Sha256::digest(parts.join("\0").as_bytes()))
}

fn decimal(value: &str, field: &str) -> Result<Decimal, BatchError> {
    Decimal::from_str(value).map_err(|error| {
        tracing::error!(field, error = %error, "parse batch image decimal");
        BatchError::internal(
            "BATCH_IMAGE_SETTLEMENT_PRICING_MISSING",
            "batch image settlement pricing is invalid",
        )
    })
}

fn row_decimal(row: &PgRow, field: &str) -> Result<Decimal, BatchError> {
    decimal(&row.try_get::<String, _>(field)?, field)
}

fn decimal_value(value: Decimal) -> Value {
    serde_json::from_str(&value.to_string()).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn value_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn query_parameters(query: Option<&str>) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

fn query_limit(
    query: &HashMap<String, String>,
    default: usize,
    maximum: usize,
) -> Result<usize, BatchError> {
    let limit = query
        .get("limit")
        .map_or(Ok(default), |value| value.parse::<usize>())
        .map_err(|_| {
            BatchError::bad_request("BATCH_IMAGE_INVALID_ITEMS", "invalid pagination limit")
        })?;
    Ok(if limit == 0 || limit > maximum {
        default
    } else {
        limit
    })
}

fn query_offset(query: &HashMap<String, String>) -> Result<usize, BatchError> {
    query
        .get("cursor")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .map_err(|_| {
            BatchError::bad_request("BATCH_IMAGE_INVALID_ITEMS", "invalid pagination cursor")
        })
}

fn normalize_list_status(status: Option<&str>) -> Result<&str, BatchError> {
    match status.unwrap_or_default().trim() {
        "" | "all" => Ok(""),
        "queued" => Ok("queued"),
        "processing_results" => Ok("indexing"),
        "running" | "settling" | "completed" | "failed" | "cancelled" | "output_deleted" => {
            Ok(status.unwrap_or_default().trim())
        }
        _ => Err(BatchError::bad_request(
            "BATCH_IMAGE_INVALID_ITEMS",
            "invalid batch image status filter",
        )),
    }
}

fn normalize_item_status(status: Option<&str>) -> Result<&str, BatchError> {
    match status.unwrap_or_default().trim() {
        "" | "all" => Ok(""),
        "succeeded" | "success" => Ok("success"),
        "pending" => Ok("pending"),
        "failed" => Ok("failed"),
        _ => Err(BatchError::bad_request(
            "BATCH_IMAGE_INVALID_ITEMS",
            "invalid batch image item status filter",
        )),
    }
}

fn parse_downloaded_filter(value: Option<&str>) -> Result<Option<bool>, BatchError> {
    match value
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "all" => Ok(None),
        "true" | "1" | "yes" | "downloaded" => Ok(Some(true)),
        "false" | "0" | "no" | "not_downloaded" => Ok(Some(false)),
        _ => Err(BatchError::bad_request(
            "BATCH_IMAGE_INVALID_ITEMS",
            "invalid downloaded filter",
        )),
    }
}

fn parse_time_filter(value: Option<&str>) -> Result<Option<i64>, BatchError> {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Ok(seconds) = value.parse::<i64>() {
        return (seconds > 0).then_some(Some(seconds)).ok_or_else(|| {
            BatchError::bad_request("BATCH_IMAGE_INVALID_ITEMS", "invalid time filter")
        });
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(Some(parsed.timestamp()));
    }
    if let Ok(parsed) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Ok(parsed
            .and_hms_opt(0, 0, 0)
            .map(|date| date.and_utc().timestamp()));
    }
    Err(BatchError::bad_request(
        "BATCH_IMAGE_INVALID_ITEMS",
        "invalid time filter",
    ))
}

fn validate_batch_id(batch_id: &str) -> Result<(), BatchError> {
    if batch_id.starts_with("imgbatch_")
        && batch_id.len() <= 64
        && batch_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Ok(())
    } else {
        Err(BatchError::job_not_found())
    }
}

fn valid_custom_id(custom_id: &str) -> bool {
    !custom_id.is_empty()
        && custom_id.len() <= 255
        && custom_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_filename(value: &str, extension: &str) -> String {
    let mut value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    while value.contains("..") {
        value = value.replace("..", "_");
    }
    let value = value.trim_matches(['.', ' ']);
    let value = if value.is_empty() { "image" } else { value };
    if extension.is_empty() {
        value.to_owned()
    } else {
        format!("{value}.{}", extension.trim_start_matches('.'))
    }
}

fn sanitize_public_error(message: &str) -> String {
    let message = if ["gs://", "files/", "projects/"]
        .into_iter()
        .any(|marker| message.contains(marker))
    {
        "upstream provider operation failed"
    } else {
        message.trim()
    };
    message.chars().take(500).collect()
}

fn json_response(value: Value) -> Response {
    Json(value).into_response()
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or_default()
}

#[derive(Debug)]
pub(crate) struct BatchError {
    status: StatusCode,
    code: String,
    message: String,
}

impl BatchError {
    fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    fn upstream(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, code, message)
    }

    fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, code, message)
    }

    fn job_not_found() -> Self {
        Self::not_found("BATCH_IMAGE_NOT_FOUND", "batch image job not found")
    }

    fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "method not allowed",
        )
    }
}

impl fmt::Display for BatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BatchError {}

impl IntoResponse for BatchError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": {
                    "type": "invalid_request_error",
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

impl From<AuthError> for BatchError {
    fn from(error: AuthError) -> Self {
        let message = if error.status_code() == StatusCode::INTERNAL_SERVER_ERROR {
            "authentication service is unavailable".to_owned()
        } else {
            error.code().to_owned()
        };
        Self::new(error.status_code(), error.code(), message)
    }
}

impl From<crate::repository::RepositoryError> for BatchError {
    fn from(error: crate::repository::RepositoryError) -> Self {
        tracing::error!(error = %error, "batch image repository operation failed");
        Self::internal("INTERNAL_ERROR", "database operation failed")
    }
}

impl From<sqlx::Error> for BatchError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "batch image PostgreSQL operation failed");
        Self::internal("INTERNAL_ERROR", "database operation failed")
    }
}

impl From<serde_json::Error> for BatchError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(error = %error, "batch image JSON operation failed");
        Self::internal("INTERNAL_ERROR", "JSON operation failed")
    }
}

impl From<crate::billing::DecimalError> for BatchError {
    fn from(error: crate::billing::DecimalError) -> Self {
        tracing::error!(error = %error, "batch image billing arithmetic failed");
        Self::internal(
            "BATCH_IMAGE_SETTLEMENT_PRICING_MISSING",
            "batch image billing arithmetic failed",
        )
    }
}

impl From<zip::ZipError> for BatchError {
    fn from(error: zip::ZipError) -> Self {
        tracing::error!(error = %error, "build batch image ZIP");
        Self::internal("BATCH_IMAGE_DOWNLOAD_FAILED", "batch image download failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_expands_submit_items() {
        let request = SubmitRequest {
            model: "gemini-2.5-flash-image".to_owned(),
            task_name: String::new(),
            parent_batch_id: String::new(),
            provider: String::new(),
            items: vec![SubmitItem {
                custom_id: "poster".to_owned(),
                prompt: "draw a poster".to_owned(),
                output_count: 2,
                reference_images: Vec::new(),
            }],
            response_mime_type: String::new(),
            aspect_ratio: String::new(),
            image_size: String::new(),
            metadata: HashMap::new(),
        };
        let normalized = NormalizedRequest::new(request).expect("request should be valid");
        assert_eq!(normalized.items.len(), 2);
        assert_eq!(normalized.items[0].custom_id, "poster_01");
        assert_eq!(normalized.items[1].custom_id, "poster_02");
    }

    #[test]
    fn parses_gemini_output_images() {
        let output = br#"{"key":"item_1","response":{"candidates":[{"content":{"parts":[{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}}]}}]}}
"#;
        let items = parse_provider_output(output).expect("output should parse");
        let item = items.get("item_1").expect("item should exist");
        assert_eq!(item.images.len(), 1);
        assert_eq!(item.images[0].extension(), "png");
    }

    #[test]
    fn bundled_image_price_is_available() {
        assert!(bundled_image_unit_price("gemini-2.5-flash-image").is_some());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a fully migrated disposable PostgreSQL database"]
    async fn postgres_expired_output_cleanup_claim_is_durable() {
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let parsed = url::Url::parse(&database_url).unwrap();
        assert!(parsed.path().trim_matches('/').ends_with("_test"));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let batch_id = format!("rust-cleanup-{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            r"
INSERT INTO batch_image_jobs (
    batch_id, user_id, provider, model, status, item_count,
    estimated_cost, output_expires_at, settled_at
) VALUES ($1, 1, 'gemini', 'gemini-2.5-flash-image', 'completed', 1,
          0, NOW() - INTERVAL '1 minute', NOW())
",
        )
        .bind(&batch_id)
        .execute(&pool)
        .await
        .unwrap();

        let service = BatchImageService::new(pool.clone(), None).unwrap();
        service.cleanup_expired_outputs().await.unwrap();
        let row = sqlx::query(
            "SELECT status, output_deleted_at IS NOT NULL AS deleted, output_expires_at IS NULL AS lease_cleared FROM batch_image_jobs WHERE batch_id = $1",
        )
        .bind(&batch_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.try_get::<String, _>("status").unwrap(),
            "output_deleted"
        );
        assert!(row.try_get::<bool, _>("deleted").unwrap());
        assert!(row.try_get::<bool, _>("lease_cleared").unwrap());

        sqlx::query("DELETE FROM batch_image_jobs WHERE batch_id = $1")
            .bind(&batch_id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a fully migrated disposable PostgreSQL database"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_hold_idempotency_and_cancel_release_are_atomic() {
        use sqlx::postgres::PgPoolOptions;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored database test");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let group_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO groups (
    name, platform, status, subscription_type, allow_batch_image_generation,
    image_price_1k, batch_image_discount_multiplier, batch_image_hold_multiplier
) VALUES ($1, 'gemini', 'active', 'standard', TRUE, 1, 0.5, 0.6)
RETURNING id
",
        )
        .bind(format!("rust-batch-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert batch image group");
        let user_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users (email, password_hash, balance) VALUES ($1, 'test', 10) RETURNING id",
        )
        .bind(format!("rust-batch-{suffix}@example.invalid"))
        .fetch_one(&pool)
        .await
        .expect("insert batch image user");
        let api_key_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO api_keys (user_id, key, name, group_id)
VALUES ($1, $2, 'rust batch', $3)
RETURNING id
",
        )
        .bind(user_id)
        .bind(format!("sk-rust-batch-{suffix}"))
        .bind(group_id)
        .fetch_one(&pool)
        .await
        .expect("insert batch image API key");
        let account_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO accounts (name, platform, type, credentials, status, schedulable)
VALUES ($1, 'gemini', 'apikey', $2::jsonb, 'active', TRUE)
RETURNING id
",
        )
        .bind(format!("rust-batch-{suffix}"))
        .bind(
            json!({
                "api_key": "test-provider-key",
                "model_mapping": { "gemini-2.5-flash-image": "gemini-2.5-flash-image" }
            })
            .to_string(),
        )
        .fetch_one(&pool)
        .await
        .expect("insert batch image account");
        sqlx::query(
            "INSERT INTO account_groups (account_id, group_id, priority) VALUES ($1, $2, 1)",
        )
        .bind(account_id)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("bind batch image account to group");

        let service =
            BatchImageService::new(pool.clone(), None).expect("build batch image service");
        let owner = Owner {
            user_id,
            api_key_id,
            group_id: Some(group_id),
        };
        let request = NormalizedRequest::new(SubmitRequest {
            model: "gemini-2.5-flash-image".to_owned(),
            task_name: "atomic test".to_owned(),
            parent_batch_id: String::new(),
            provider: "gemini_api".to_owned(),
            items: vec![SubmitItem {
                custom_id: "item_1".to_owned(),
                prompt: "draw an integration test".to_owned(),
                output_count: 1,
                reference_images: Vec::new(),
            }],
            response_mime_type: String::new(),
            aspect_ratio: String::new(),
            image_size: "1K".to_owned(),
            metadata: HashMap::new(),
        })
        .expect("normalize batch image request");
        let selection = service
            .select_account(&owner, &request.model)
            .await
            .expect("select test account");
        let pricing = service
            .pricing(&owner, &request, &selection.account)
            .await
            .expect("resolve test pricing");
        assert_eq!(pricing.estimated_cost.to_string(), "0.5");
        assert_eq!(pricing.hold_amount.to_string(), "0.6");
        let batch_id = format!("imgbatch_{}", uuid::Uuid::new_v4().simple());
        let request_hash = request.hash().expect("hash request");
        let mut transaction = pool.begin().await.expect("begin hold transaction");
        insert_job_and_hold(
            &mut transaction,
            &owner,
            &batch_id,
            "atomic test",
            &request,
            &selection,
            &pricing,
            "atomic-idempotency-key",
            &request_hash,
        )
        .await
        .expect("insert job and reserve hold");
        insert_pending_items(&mut transaction, &batch_id, &request_hash, &request.items)
            .await
            .expect("insert pending item");
        transaction.commit().await.expect("commit hold transaction");

        let balances = sqlx::query(
            "SELECT balance::text AS balance, frozen_balance::text AS frozen FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("read held balance");
        assert_eq!(
            balances.try_get::<String, _>("balance").unwrap(),
            "9.40000000"
        );
        assert_eq!(
            balances.try_get::<String, _>("frozen").unwrap(),
            "0.60000000"
        );
        let existing = service
            .load_by_idempotency(&owner, "atomic-idempotency-key")
            .await
            .expect("load idempotent job")
            .expect("idempotent job should exist");
        assert_eq!(existing.batch_id, batch_id);

        service
            .finish_without_charge(
                &existing,
                "cancelled",
                "BATCH_IMAGE_CANCELLED",
                "integration test cancellation",
            )
            .await
            .expect("cancel and release hold");
        let released = sqlx::query(
            "SELECT balance::text AS balance, frozen_balance::text AS frozen FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("read released balance");
        assert_eq!(
            released.try_get::<String, _>("balance").unwrap(),
            "10.00000000"
        );
        assert_eq!(
            released.try_get::<String, _>("frozen").unwrap(),
            "0.00000000"
        );
        let cancelled = service
            .load_job(&batch_id)
            .await
            .expect("load cancelled job");
        assert_eq!(cancelled.status, "cancelled");

        sqlx::query("DELETE FROM usage_billing_dedup WHERE api_key_id = $1")
            .bind(api_key_id)
            .execute(&pool)
            .await
            .expect("delete billing dedup test rows");
        sqlx::query("DELETE FROM batch_image_jobs WHERE batch_id = $1")
            .bind(&batch_id)
            .execute(&pool)
            .await
            .expect("delete batch image test job");
        sqlx::query("DELETE FROM account_groups WHERE account_id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("delete test account binding");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("delete test account");
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(api_key_id)
            .execute(&pool)
            .await
            .expect("delete test API key");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete test user");
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await
            .expect("delete test group");
        pool.close().await;
    }
}
