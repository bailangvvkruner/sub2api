//! Contract-checked compatibility layer for database-backed Go admin routes.

use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Path, Request, State},
    http::{Method, StatusCode, header, header::USER_AGENT},
    response::{IntoResponse, Response},
    routing::{MethodFilter, get, on},
};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};

use super::{
    AdminApiState, AdminError, AdminIdentity, AdminService, compat_accounts,
    compat_admin_semantics, compat_external, compat_oauth, compat_ops, compat_payment,
    compat_relations, compat_resources, compat_settings, compat_special, compat_usage, compliance,
};
use crate::route_contract;

const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAGE_SIZE: i64 = 1_000;

#[derive(Clone, Copy)]
pub(super) struct Resource {
    pub table: &'static str,
    pub label: &'static str,
}

pub(super) fn router() -> Router<AdminApiState> {
    let mut router = Router::new();
    for route in route_contract::routes().filter(|route| {
        route.category.starts_with("admin/")
            && route.path.starts_with("/api/v1/admin/")
            && !has_typed_route(route.category, route.handler)
    }) {
        let Some(filter) = method_filter(route.method) else {
            continue;
        };
        router = router.route(&axum_path(route.path), on(filter, handle));
    }
    router.route("/api/v1/admin/backups/{id}/download", get(download_backup))
}

fn method_filter(method: &str) -> Option<MethodFilter> {
    match method {
        "GET" => Some(MethodFilter::GET),
        "POST" => Some(MethodFilter::POST),
        "PUT" => Some(MethodFilter::PUT),
        "PATCH" => Some(MethodFilter::PATCH),
        "DELETE" => Some(MethodFilter::DELETE),
        _ => None,
    }
}

fn axum_path(path: &str) -> String {
    let segments = path
        .trim_matches('/')
        .split('/')
        .map(|segment| {
            segment.strip_prefix(':').map_or_else(
                || {
                    segment
                        .strip_prefix('*')
                        .map_or_else(|| segment.to_owned(), |name| format!("{{*{name}}}"))
                },
                |name| format!("{{{name}}}"),
            )
        })
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn has_typed_route(category: &str, handler: &str) -> bool {
    if handler == "h.ListPages" {
        return true;
    }
    if category == "admin/ops-websocket" {
        return true;
    }
    if matches!(
        category,
        "admin/affiliates"
            | "admin/announcements"
            | "admin/channels"
            | "admin/channel-monitors"
            | "admin/channel-monitor-templates"
    ) {
        return true;
    }
    matches!(
        handler,
        "h.Admin.User.List"
            | "h.Admin.User.Create"
            | "h.Admin.User.GetByID"
            | "h.Admin.User.Update"
            | "h.Admin.User.Delete"
            | "h.Admin.Group.List"
            | "h.Admin.Group.Create"
            | "h.Admin.Group.GetByID"
            | "h.Admin.Group.Update"
            | "h.Admin.Group.Delete"
            | "h.Admin.Account.List"
            | "h.Admin.Account.Create"
            | "h.Admin.Account.GetByID"
            | "h.Admin.Account.Update"
            | "h.Admin.Account.Delete"
            | "h.Admin.Account.Test"
            | "h.Admin.Proxy.List"
            | "h.Admin.Proxy.Create"
            | "h.Admin.Proxy.GetByID"
            | "h.Admin.Proxy.Update"
            | "h.Admin.Proxy.Delete"
            | "h.Admin.APIKey.UpdateGroup"
            | "h.Admin.Setting.GetSettings"
            | "h.Admin.Setting.UpdateSettings"
    )
}

pub(super) async fn handle(State(state): State<AdminApiState>, request: Request) -> Response {
    let Some(identity) = request.extensions().get::<AdminIdentity>().cloned() else {
        return AdminError::Unauthorized.into_response();
    };
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_owned();
    let Some(contract) =
        route_contract::find(&method, &path).filter(|route| route.category.starts_with("admin/"))
    else {
        return AdminError::NotFound("administrator route").into_response();
    };
    let query = query_map(uri.query());
    let ip_address = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip().to_string());
    let user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match to_bytes(request.into_body(), MAX_ADMIN_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => return AdminError::BadRequest(error.to_string()).into_response(),
    };
    let payload = if body.is_empty() {
        Value::Object(Map::new())
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) => value,
            Err(error) => {
                return AdminError::BadRequest(format!("invalid JSON request: {error}"))
                    .into_response();
            }
        }
    };
    match dispatch(
        &state.service,
        &identity,
        contract.handler,
        contract.category,
        &method,
        &path,
        &query,
        ip_address.as_deref(),
        user_agent.as_deref(),
        payload,
    )
    .await
    {
        Ok(data) => success(contract.handler, data),
        Err(error) => error.into_response(),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn dispatch(
    service: &AdminService,
    actor: &AdminIdentity,
    handler: &str,
    category: &str,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    payload: Value,
) -> Result<Value, AdminError> {
    let pool = service.pool();
    match handler {
        "h.Admin.Compliance.GetStatus" => {
            return compliance::status(pool, actor.user_id).await;
        }
        "h.Admin.Compliance.Accept" => {
            return compliance::accept(pool, actor.user_id, &payload, ip_address, user_agent).await;
        }
        _ => {}
    }
    if let Some(result) = compat_relations::dispatch(service, handler, path, query).await {
        return result;
    }

    if let Some(result) =
        compat_usage::dispatch(service, actor, handler, path, query, payload.clone()).await
    {
        return result;
    }

    if let Some(result) =
        compat_admin_semantics::dispatch(pool, handler, path, query, payload.clone()).await
    {
        return result;
    }

    // These resource handlers expose filtered/derived DTOs, patch validation,
    // cache notifications, or scheduler state that generic table CRUD loses.
    if let Some(result) =
        compat_resources::dispatch(pool, actor, handler, path, query, payload.clone()).await
    {
        return result;
    }

    // Payment plan/provider/order reads have validation, redaction, audit-log,
    // and pending-order invariants that generic table CRUD cannot preserve.
    if let Some(result) =
        compat_payment::dispatch(pool, actor, handler, path, query, payload.clone()).await
    {
        return result;
    }

    // Ops has non-CRUD filtering, validation, aggregation, and audit semantics.
    // It must claim its routes before the generic alert resource mapping below.
    if let Some(result) = compat_ops::dispatch(
        pool,
        actor,
        handler,
        category,
        method,
        path,
        query,
        payload.clone(),
    )
    .await
    {
        return result;
    }

    if let Some(resource) = resource_for(category, path)
        && let Some(operation) = crud_operation(handler)
    {
        return match operation {
            CrudOperation::List => list_resource(pool, resource, query).await,
            CrudOperation::Get => {
                get_resource(pool, resource, required_path_id(path, resource.label)?).await
            }
            CrudOperation::Create => create_resource(pool, resource, payload).await,
            CrudOperation::Update => {
                update_resource(
                    pool,
                    resource,
                    required_path_id(path, resource.label)?,
                    payload,
                )
                .await
            }
            CrudOperation::Delete => {
                delete_resource(pool, resource, required_path_id(path, resource.label)?).await
            }
        };
    }

    let relation = match handler {
        "h.Admin.Announcement.ListReadStatus" => {
            Some(("announcement_reads", "announcement_id", "announcement"))
        }
        "h.Admin.Promo.GetUsages" => Some(("promo_code_usages", "promo_code_id", "promo code")),
        "h.Admin.ScheduledTest.ListResults" => {
            Some(("scheduled_test_results", "plan_id", "scheduled test plan"))
        }
        "h.Admin.ChannelMonitor.History" => {
            Some(("channel_monitor_histories", "monitor_id", "channel monitor"))
        }
        "h.Admin.ChannelMonitorTemplate.AssociatedMonitors" => Some((
            "channel_monitors",
            "template_id",
            "channel monitor template",
        )),
        "h.Admin.User.GetUserAPIKeys" => Some(("api_keys", "user_id", "user")),
        "h.Admin.User.GetUserPlatformQuotas" => Some(("user_platform_quotas", "user_id", "user")),
        "h.Admin.Subscription.ListByUser" => Some(("user_subscriptions", "user_id", "user")),
        "h.Admin.Subscription.ListByGroup" => Some(("user_subscriptions", "group_id", "group")),
        "h.Admin.Group.GetGroupAPIKeys" => Some(("api_keys", "group_id", "group")),
        _ => None,
    };
    if let Some((table, foreign_key, label)) = relation {
        return relation_list(
            pool,
            table,
            foreign_key,
            required_path_id(path, label)?,
            query,
        )
        .await;
    }

    if let Some(result) = compat_external::dispatch(
        pool,
        actor,
        handler,
        category,
        method,
        path,
        query,
        payload.clone(),
    )
    .await
    {
        return result;
    }

    if let Some(result) = compat_accounts::dispatch(
        pool,
        handler,
        category,
        method,
        path,
        query,
        payload.clone(),
    )
    .await
    {
        return result;
    }

    if let Some(result) = compat_oauth::dispatch(
        pool,
        handler,
        category,
        method,
        path,
        query,
        payload.clone(),
    )
    .await
    {
        return result;
    }

    if let Some(result) =
        compat_settings::dispatch(pool, handler, method, path, payload.clone()).await
    {
        return result;
    }

    if let Some(result) =
        compat_special::dispatch(pool, handler, category, method, path, query, payload).await
    {
        return result;
    }
    Err(AdminError::Unavailable(format!(
        "administrator operation {} is not available in this runtime",
        handler.rsplit('.').next().unwrap_or(handler)
    )))
}

async fn download_backup(State(state): State<AdminApiState>, Path(id): Path<String>) -> Response {
    let (path, file_name) =
        match compat_external::local_backup_path(state.service.pool(), &id).await {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return AdminError::NotFound("backup file").into_response();
        }
        Err(error) => {
            return AdminError::Probe(format!("cannot open backup file: {error}")).into_response();
        }
    };
    let stream = tokio_util::io::ReaderStream::new(file);
    let disposition = format!("attachment; filename=\"{file_name}\"");
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[derive(Clone, Copy)]
enum CrudOperation {
    List,
    Get,
    Create,
    Update,
    Delete,
}

fn crud_operation(handler: &str) -> Option<CrudOperation> {
    match handler.rsplit('.').next()? {
        "List" | "ListDefinitions" | "ListPlans" | "ListProviders" | "ListOrders"
        | "ListAlertRules" | "ListAlertEvents" => Some(CrudOperation::List),
        "Get" | "GetByID" | "GetOrderDetail" | "GetAlertEvent" => Some(CrudOperation::Get),
        "Create" | "CreateDefinition" | "CreatePlan" | "CreateProvider" | "CreateAlertRule" => {
            Some(CrudOperation::Create)
        }
        "Update" | "UpdateDefinition" | "UpdatePlan" | "UpdateProvider" | "UpdateAlertRule" => {
            Some(CrudOperation::Update)
        }
        "Delete" | "DeleteDefinition" | "DeletePlan" | "DeleteProvider" | "DeleteAlertRule" => {
            Some(CrudOperation::Delete)
        }
        _ => None,
    }
}

fn resource_for(category: &str, path: &str) -> Option<Resource> {
    let resource = match category {
        "admin/announcements" => Resource {
            table: "announcements",
            label: "announcement",
        },
        "admin/promo-codes" => Resource {
            table: "promo_codes",
            label: "promo code",
        },
        "admin/redeem-codes" => Resource {
            table: "redeem_codes",
            label: "redeem code",
        },
        "admin/subscriptions" => Resource {
            table: "user_subscriptions",
            label: "subscription",
        },
        "admin/user-attributes" => Resource {
            table: "user_attribute_definitions",
            label: "user attribute",
        },
        "admin/scheduled-test-plans" => Resource {
            table: "scheduled_test_plans",
            label: "scheduled test plan",
        },
        "admin/error-passthrough-rules" => Resource {
            table: "error_passthrough_rules",
            label: "error passthrough rule",
        },
        "admin/tls-fingerprint-profiles" => Resource {
            table: "tls_fingerprint_profiles",
            label: "TLS fingerprint profile",
        },
        "admin/channels" => Resource {
            table: "channels",
            label: "channel",
        },
        "admin/channel-monitors" => Resource {
            table: "channel_monitors",
            label: "channel monitor",
        },
        "admin/channel-monitor-templates" => Resource {
            table: "channel_monitor_request_templates",
            label: "channel monitor template",
        },
        "admin/payment" if path.contains("/plans") => Resource {
            table: "subscription_plans",
            label: "subscription plan",
        },
        "admin/payment" if path.contains("/providers") => Resource {
            table: "payment_provider_instances",
            label: "payment provider",
        },
        "admin/payment" if path.contains("/orders") => Resource {
            table: "payment_orders",
            label: "payment order",
        },
        "admin/ops" if path.contains("/alert-rules") => Resource {
            table: "ops_alert_rules",
            label: "alert rule",
        },
        "admin/ops" if path.contains("/alert-events") => Resource {
            table: "ops_alert_events",
            label: "alert event",
        },
        _ => return None,
    };
    Some(resource)
}

pub(super) async fn list_resource(
    pool: &PgPool,
    resource: Resource,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let columns = table_columns(pool, resource.table).await?;
    let page = query_i64(query, "page", 1).max(1);
    let page_size = query_i64(query, "page_size", 20).clamp(1, MAX_PAGE_SIZE);
    let search = query.get("search").or_else(|| query.get("keyword"));
    let status = query.get("status");
    let deleted = if columns.contains("deleted_at") {
        " AND row.deleted_at IS NULL"
    } else {
        ""
    };
    let searchable = [
        "name",
        "email",
        "username",
        "code",
        "description",
        "out_trade_no",
    ]
    .into_iter()
    .filter(|column| columns.contains(*column))
    .map(|column| format!("COALESCE(row.{column}::text, '')"))
    .collect::<Vec<_>>();
    let search_condition = if searchable.is_empty() {
        "$1::text IS NULL".to_owned()
    } else {
        format!(
            "($1::text IS NULL OR concat_ws(' ', {}) ILIKE '%' || $1 || '%')",
            searchable.join(", ")
        )
    };
    let status_condition = if columns.contains("status") {
        "($2::text IS NULL OR row.status::text = $2)"
    } else {
        "$2::text IS NULL"
    };
    let order_column = ["updated_at", "created_at", "id"]
        .into_iter()
        .find(|column| columns.contains(*column))
        .or_else(|| columns.iter().map(String::as_str).next())
        .ok_or_else(|| AdminError::Unavailable(format!("{} has no columns", resource.table)))?;
    let sql = format!(
        "SELECT {} AS data FROM {} row WHERE {} AND {}{} ORDER BY row.{} DESC LIMIT $3 OFFSET $4",
        redacted_json("row"),
        resource.table,
        search_condition,
        status_condition,
        deleted,
        order_column
    );
    let rows = sqlx::query(&sql)
        .bind(search.map(String::as_str))
        .bind(status.map(String::as_str))
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data"))
        .collect::<Result<Vec<_>, _>>()?;
    let count_sql = format!(
        "SELECT COUNT(*)::bigint FROM {} row WHERE {} AND {}{}",
        resource.table, search_condition, status_condition, deleted
    );
    let total = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(search.map(String::as_str))
        .bind(status.map(String::as_str))
        .fetch_one(pool)
        .await?;
    Ok(json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": ((total + page_size - 1) / page_size).max(1),
    }))
}

pub(super) async fn get_resource(
    pool: &PgPool,
    resource: Resource,
    id: i64,
) -> Result<Value, AdminError> {
    let columns = table_columns(pool, resource.table).await?;
    let deleted = if columns.contains("deleted_at") {
        " AND row.deleted_at IS NULL"
    } else {
        ""
    };
    let sql = format!(
        "SELECT {} AS data FROM {} row WHERE row.id = $1{}",
        redacted_json("row"),
        resource.table,
        deleted
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound(resource.label))
}

pub(super) async fn create_resource(
    pool: &PgPool,
    resource: Resource,
    payload: Value,
) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let columns = writable_columns(pool, resource.table, &object).await?;
    if columns.is_empty() {
        return Err(AdminError::BadRequest(
            "no writable fields were provided".to_owned(),
        ));
    }
    let source = columns
        .iter()
        .map(|column| format!("input.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {} AS inserted ({}) SELECT {} FROM jsonb_populate_record(NULL::{}, $1::jsonb) input RETURNING {}",
        resource.table,
        columns.join(", "),
        source,
        resource.table,
        redacted_json("inserted")
    );
    let raw = serde_json::to_string(&Value::Object(object))
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    Ok(sqlx::query_scalar::<_, Value>(&sql)
        .bind(raw)
        .fetch_one(pool)
        .await?)
}

pub(super) async fn update_resource(
    pool: &PgPool,
    resource: Resource,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let columns = writable_columns(pool, resource.table, &object).await?;
    if columns.is_empty() {
        return Err(AdminError::BadRequest(
            "no writable fields were provided".to_owned(),
        ));
    }
    let all_columns = table_columns(pool, resource.table).await?;
    let mut assignments = columns
        .iter()
        .map(|column| format!("{column} = input.{column}"))
        .collect::<Vec<_>>();
    if all_columns.contains("updated_at") {
        assignments.push("updated_at = NOW()".to_owned());
    }
    let deleted = if all_columns.contains("deleted_at") {
        " AND target.deleted_at IS NULL"
    } else {
        ""
    };
    let sql = format!(
        "UPDATE {} target SET {} FROM jsonb_populate_record(NULL::{}, $2::jsonb) input WHERE target.id = $1{} RETURNING {}",
        resource.table,
        assignments.join(", "),
        resource.table,
        deleted,
        redacted_json("target")
    );
    let raw = serde_json::to_string(&Value::Object(object))
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(raw)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound(resource.label))
}

pub(super) async fn delete_resource(
    pool: &PgPool,
    resource: Resource,
    id: i64,
) -> Result<Value, AdminError> {
    let columns = table_columns(pool, resource.table).await?;
    let sql = if columns.contains("deleted_at") {
        format!(
            "UPDATE {} SET deleted_at = NOW(){} WHERE id = $1 AND deleted_at IS NULL",
            resource.table,
            if columns.contains("updated_at") {
                ", updated_at = NOW()"
            } else {
                ""
            }
        )
    } else {
        format!("DELETE FROM {} WHERE id = $1", resource.table)
    };
    let result = sqlx::query(&sql).bind(id).execute(pool).await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound(resource.label));
    }
    Ok(json!({ "message": format!("{} deleted", resource.label) }))
}

pub(super) async fn relation_list(
    pool: &PgPool,
    table: &'static str,
    foreign_key: &'static str,
    id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let columns = table_columns(pool, table).await?;
    if !columns.contains(foreign_key) {
        return Err(AdminError::Unavailable(format!(
            "relation {table}.{foreign_key} is unavailable"
        )));
    }
    let page = query_i64(query, "page", 1).max(1);
    let page_size = query_i64(query, "page_size", 20).clamp(1, MAX_PAGE_SIZE);
    let deleted = if columns.contains("deleted_at") {
        " AND row.deleted_at IS NULL"
    } else {
        ""
    };
    let order = ["created_at", "id"]
        .into_iter()
        .find(|column| columns.contains(*column))
        .unwrap_or(foreign_key);
    let sql = format!(
        "SELECT {} AS data FROM {} row WHERE row.{} = $1{} ORDER BY row.{} DESC LIMIT $2 OFFSET $3",
        redacted_json("row"),
        table,
        foreign_key,
        deleted,
        order
    );
    let rows = sqlx::query(&sql)
        .bind(id)
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data"))
        .collect::<Result<Vec<_>, _>>()?;
    let count_sql =
        format!("SELECT COUNT(*)::bigint FROM {table} row WHERE row.{foreign_key} = $1{deleted}");
    let total = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }))
}

pub(super) async fn table_columns(
    pool: &PgPool,
    table: &str,
) -> Result<HashSet<String>, AdminError> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Err(AdminError::Unavailable(format!(
            "database resource {table} is unavailable"
        )));
    }
    Ok(rows.into_iter().collect())
}

async fn writable_columns(
    pool: &PgPool,
    table: &str,
    object: &Map<String, Value>,
) -> Result<Vec<String>, AdminError> {
    let available = table_columns(pool, table).await?;
    let protected = [
        "id",
        "created_at",
        "updated_at",
        "deleted_at",
        "password_hash",
        "api_key_encrypted",
        "auth_generation",
        "used_by",
        "used_at",
    ];
    let mut columns = object
        .keys()
        .filter(|column| available.contains(*column) && !protected.contains(&column.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    columns.sort();
    Ok(columns)
}

pub(super) fn payload_object(payload: Value) -> Result<Map<String, Value>, AdminError> {
    match payload {
        Value::Object(object) => Ok(object),
        _ => Err(AdminError::BadRequest(
            "request body must be a JSON object".to_owned(),
        )),
    }
}

pub(super) fn redacted_json(alias: &str) -> String {
    format!(
        "to_jsonb({alias}) - ARRAY['password_hash','password','credentials','api_key_encrypted','config','secret','access_token','refresh_token']::text[]"
    )
}

pub(super) fn required_path_id(path: &str, resource: &'static str) -> Result<i64, AdminError> {
    path.trim_matches('/')
        .split('/')
        .find_map(|segment| segment.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| AdminError::BadRequest(format!("valid {resource} id is required")))
}

fn query_map(raw: Option<&str>) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

pub(super) fn query_i64(query: &BTreeMap<String, String>, key: &str, default: i64) -> i64 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn success(handler: &str, data: Value) -> Response {
    if matches!(
        handler,
        "h.Admin.ScheduledTest.ListByAccount"
            | "h.Admin.ScheduledTest.ListResults"
            | "h.Admin.Usage.PendingStats"
    ) {
        return (StatusCode::OK, Json(data)).into_response();
    }
    let mut body = json!({ "code": 0, "message": "success" });
    body["data"] = data;
    let status = if matches!(
        handler,
        "adminPaymentHandler.CreatePlan" | "adminPaymentHandler.CreateProvider"
    ) {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_contract_admin_paths_reach_the_dispatcher() {
        let route = route_contract::find(&Method::GET, "/api/v1/admin/ops/errors").unwrap();
        assert!(route.category.starts_with("admin/"));
        assert!(route_contract::find(&Method::GET, "/api/v1/admin/not-real").is_none());
    }

    #[test]
    fn resource_mapping_uses_static_table_names() {
        assert_eq!(
            resource_for("admin/promo-codes", "/api/v1/admin/promo-codes")
                .unwrap()
                .table,
            "promo_codes"
        );
        assert!(resource_for("admin/unknown", "/api/v1/admin/unknown").is_none());
    }

    #[test]
    fn converts_gin_parameters_to_axum_parameters() {
        assert_eq!(
            axum_path("/api/v1/admin/users/:id/subscriptions"),
            "/api/v1/admin/users/{id}/subscriptions"
        );
        assert_eq!(
            axum_path("/api/v1/admin/pages/*filename"),
            "/api/v1/admin/pages/{*filename}"
        );
    }

    #[test]
    fn every_go_administrator_handler_has_a_production_owner() {
        let sources = [
            include_str!("compat.rs"),
            include_str!("compat_accounts.rs"),
            include_str!("compat_admin_semantics.rs"),
            include_str!("compat_external.rs"),
            include_str!("compat_oauth.rs"),
            include_str!("compat_ops.rs"),
            include_str!("compat_payment.rs"),
            include_str!("compat_relations.rs"),
            include_str!("compat_resources.rs"),
            include_str!("compat_settings.rs"),
            include_str!("compat_special.rs"),
            include_str!("compat_usage.rs"),
            include_str!("http.rs"),
        ];
        let production = sources
            .iter()
            .map(|source| {
                source
                    .split_once("#[cfg(test)]")
                    .map_or(*source, |part| part.0)
            })
            .collect::<Vec<_>>();
        let routes = route_contract::routes()
            .filter(|route| {
                route.category.starts_with("admin/")
                    && !has_typed_route(route.category, route.handler)
            })
            .collect::<Vec<_>>();
        assert!(!routes.is_empty());
        let unowned = routes
            .iter()
            .filter(|route| {
                let full_handler = format!("\"{}\"", route.handler);
                let setting_operation = route
                    .handler
                    .strip_prefix("h.Admin.Setting.")
                    .map(|operation| format!("\"{operation}\""));
                !production.iter().any(|source| {
                    source.contains(&full_handler)
                        || setting_operation
                            .as_ref()
                            .is_some_and(|operation| source.contains(operation))
                })
            })
            .map(|route| format!("{} {} -> {}", route.method, route.path, route.handler))
            .collect::<Vec<_>>();
        assert!(
            unowned.is_empty(),
            "unowned administrator routes: {unowned:#?}"
        );
    }
}
