#![allow(clippy::too_many_lines)]

use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post, put},
};
use chrono::{DateTime, Days, NaiveDate};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

use super::{
    http::AdminApiState,
    models::{AdminError, Page},
};

const DEFAULT_REBATE_RATE_PERCENT: f64 = 20.0;
const DEFAULT_PAGE_SIZE: i64 = 20;
const MAX_PAGE_SIZE: i64 = 100;

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .route("/api/v1/admin/affiliates/invites", get(list_invites))
        .route("/api/v1/admin/affiliates/rebates", get(list_rebates))
        .route("/api/v1/admin/affiliates/transfers", get(list_transfers))
        .route("/api/v1/admin/affiliates/users", get(list_users))
        .route("/api/v1/admin/affiliates/users/lookup", get(lookup_users))
        .route(
            "/api/v1/admin/affiliates/users/batch-rate",
            post(batch_set_rate),
        )
        .route(
            "/api/v1/admin/affiliates/users/{user_id}/overview",
            get(user_overview),
        )
        .route(
            "/api/v1/admin/affiliates/users/{user_id}",
            put(update_user).delete(clear_user),
        )
}

#[derive(Debug, Serialize)]
struct Envelope<T> {
    code: u16,
    message: &'static str,
    data: T,
}

impl<T> Envelope<T> {
    const fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success",
            data,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AffiliateQuery {
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_page_size")]
    page_size: i64,
    #[serde(default)]
    search: String,
    #[serde(default)]
    start_at: String,
    #[serde(default)]
    end_at: String,
    #[serde(default)]
    sort_by: String,
    #[serde(default)]
    sort_order: String,
    #[serde(default, rename = "timezone")]
    _timezone: String,
}

const fn default_page() -> i64 {
    1
}

const fn default_page_size() -> i64 {
    DEFAULT_PAGE_SIZE
}

impl AffiliateQuery {
    fn normalized(mut self) -> Self {
        self.page = self.page.max(1);
        self.page_size = self.page_size.clamp(1, MAX_PAGE_SIZE);
        self.search = self.search.trim().chars().take(100).collect();
        self.sort_by = self.sort_by.trim().to_ascii_lowercase();
        self.sort_order = self.sort_order.trim().to_ascii_lowercase();
        self
    }

    const fn offset(&self) -> i64 {
        (self.page - 1) * self.page_size
    }

    fn start_time(&self) -> Option<String> {
        normalize_filter_time(&self.start_at, false)
    }

    fn end_time(&self) -> Option<String> {
        normalize_filter_time(&self.end_at, true)
    }

    fn descending(&self) -> bool {
        self.sort_order != "asc"
    }

    fn page<T>(&self, items: Vec<T>, total: i64) -> Page<T> {
        let query = super::models::PageQuery {
            page: self.page,
            page_size: self.page_size,
            search: None,
            status: None,
            role: None,
            platform: None,
        };
        Page::new(items, total, &query)
    }
}

#[derive(Debug, Serialize)]
struct AffiliateAdminEntry {
    user_id: i64,
    email: String,
    username: String,
    aff_code: String,
    aff_code_custom: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    aff_rebate_rate_percent: Option<f64>,
    aff_count: i32,
}

#[derive(Debug, Serialize)]
struct AffiliateUserSummary {
    id: i64,
    email: String,
    username: String,
}

#[derive(Debug, Serialize)]
struct InviteRecord {
    inviter_id: i64,
    inviter_email: String,
    inviter_username: String,
    invitee_id: i64,
    invitee_email: String,
    invitee_username: String,
    aff_code: String,
    total_rebate: f64,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct RebateRecord {
    order_id: i64,
    out_trade_no: String,
    inviter_id: i64,
    inviter_email: String,
    inviter_username: String,
    invitee_id: i64,
    invitee_email: String,
    invitee_username: String,
    order_amount: f64,
    pay_amount: f64,
    rebate_amount: f64,
    payment_type: String,
    order_status: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct TransferRecord {
    ledger_id: i64,
    user_id: i64,
    user_email: String,
    username: String,
    amount: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance_after: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_quota_after: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frozen_quota_after: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    history_quota_after: Option<f64>,
    snapshot_available: bool,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct AffiliateUserOverview {
    user_id: i64,
    email: String,
    username: String,
    aff_code: String,
    rebate_rate_percent: f64,
    invited_count: i32,
    rebated_invitee_count: i32,
    available_quota: f64,
    history_quota: f64,
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    #[serde(default)]
    q: String,
}

#[derive(Debug, Deserialize)]
struct UpdateAffiliateUserRequest {
    aff_code: Option<String>,
    aff_rebate_rate_percent: Option<f64>,
    #[serde(default)]
    clear_rebate_rate: bool,
}

#[derive(Debug, Deserialize)]
struct BatchSetRateRequest {
    user_ids: Vec<i64>,
    aff_rebate_rate_percent: Option<f64>,
    #[serde(default)]
    clear: bool,
}

async fn list_users(
    State(state): State<AdminApiState>,
    Query(query): Query<AffiliateQuery>,
) -> Result<Json<Envelope<Page<AffiliateAdminEntry>>>, AdminError> {
    let query = query.normalized();
    let pattern = format!("%{}%", query.search);
    let total = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)
FROM user_affiliates affiliate
JOIN users u ON u.id = affiliate.user_id
WHERE (affiliate.aff_code_custom = TRUE OR affiliate.aff_rebate_rate_percent IS NOT NULL)
  AND u.deleted_at IS NULL
  AND (u.email ILIKE $1 OR u.username ILIKE $1)
",
    )
    .bind(&pattern)
    .fetch_one(state.service.pool())
    .await?;
    let rows = sqlx::query(
        r"
SELECT affiliate.user_id, COALESCE(u.email, '') AS email,
       COALESCE(u.username, '') AS username, affiliate.aff_code,
       affiliate.aff_code_custom,
       affiliate.aff_rebate_rate_percent::double precision AS rate,
       affiliate.aff_count
FROM user_affiliates affiliate
JOIN users u ON u.id = affiliate.user_id
WHERE (affiliate.aff_code_custom = TRUE OR affiliate.aff_rebate_rate_percent IS NOT NULL)
  AND u.deleted_at IS NULL
  AND (u.email ILIKE $1 OR u.username ILIKE $1)
ORDER BY affiliate.updated_at DESC
LIMIT $2 OFFSET $3
",
    )
    .bind(pattern)
    .bind(query.page_size)
    .bind(query.offset())
    .fetch_all(state.service.pool())
    .await?;
    let items = rows
        .iter()
        .map(affiliate_admin_entry_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Envelope::success(query.page(items, total))))
}

async fn lookup_users(
    State(state): State<AdminApiState>,
    Query(query): Query<LookupQuery>,
) -> Result<Json<Envelope<Vec<AffiliateUserSummary>>>, AdminError> {
    let keyword = query.q.trim();
    if keyword.is_empty() {
        return Ok(Json(Envelope::success(Vec::new())));
    }
    let rows = sqlx::query(
        r"
SELECT id, COALESCE(email, '') AS email, COALESCE(username, '') AS username
FROM users
WHERE deleted_at IS NULL AND (email ILIKE $1 OR username ILIKE $1)
ORDER BY email ASC, id ASC
LIMIT 20
",
    )
    .bind(format!(
        "%{}%",
        keyword.chars().take(100).collect::<String>()
    ))
    .fetch_all(state.service.pool())
    .await?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(AffiliateUserSummary {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
                username: row.try_get("username")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(Json(Envelope::success(items)))
}

async fn update_user(
    State(state): State<AdminApiState>,
    Path(user_id): Path<i64>,
    Json(request): Json<UpdateAffiliateUserRequest>,
) -> Result<Json<Envelope<serde_json::Value>>, AdminError> {
    validate_user_id(user_id)?;
    let code = request
        .aff_code
        .as_deref()
        .map(normalize_affiliate_code)
        .transpose()?;
    let rate = if request.clear_rebate_rate {
        None
    } else {
        request.aff_rebate_rate_percent
    };
    if !request.clear_rebate_rate {
        validate_rebate_rate(rate)?;
    }

    let mut transaction = state.service.pool().begin().await?;
    ensure_affiliate(&mut transaction, user_id).await?;
    if let Some(code) = code {
        sqlx::query(
            r"
UPDATE user_affiliates
SET aff_code = $2, aff_code_custom = TRUE, updated_at = NOW()
WHERE user_id = $1
",
        )
        .bind(user_id)
        .bind(code)
        .execute(&mut *transaction)
        .await
        .map_err(affiliate_write_error)?;
    }
    if request.clear_rebate_rate || request.aff_rebate_rate_percent.is_some() {
        set_rebate_rate(&mut transaction, user_id, rate).await?;
    }
    transaction.commit().await?;
    Ok(Json(Envelope::success(
        serde_json::json!({"user_id": user_id}),
    )))
}

async fn clear_user(
    State(state): State<AdminApiState>,
    Path(user_id): Path<i64>,
) -> Result<Json<Envelope<serde_json::Value>>, AdminError> {
    validate_user_id(user_id)?;
    let mut transaction = state.service.pool().begin().await?;
    ensure_affiliate(&mut transaction, user_id).await?;
    reset_affiliate_settings(&mut transaction, user_id).await?;
    transaction.commit().await?;
    Ok(Json(Envelope::success(
        serde_json::json!({"user_id": user_id}),
    )))
}

async fn batch_set_rate(
    State(state): State<AdminApiState>,
    Json(request): Json<BatchSetRateRequest>,
) -> Result<Json<Envelope<serde_json::Value>>, AdminError> {
    if request.user_ids.is_empty() {
        return Err(AdminError::BadRequest(
            "user_ids cannot be empty".to_owned(),
        ));
    }
    if !request.clear && request.aff_rebate_rate_percent.is_none() {
        return Err(AdminError::BadRequest(
            "aff_rebate_rate_percent is required unless clear=true".to_owned(),
        ));
    }
    let rate = if request.clear {
        None
    } else {
        request.aff_rebate_rate_percent
    };
    validate_rebate_rate(rate)?;
    let mut seen = HashSet::new();
    let user_ids = request
        .user_ids
        .into_iter()
        .filter(|user_id| *user_id > 0 && seen.insert(*user_id))
        .collect::<Vec<_>>();
    if user_ids.is_empty() {
        return Err(AdminError::BadRequest(
            "user_ids must contain a positive identifier".to_owned(),
        ));
    }
    let mut transaction = state.service.pool().begin().await?;
    for user_id in &user_ids {
        ensure_affiliate(&mut transaction, *user_id).await?;
    }
    sqlx::query(
        r"
UPDATE user_affiliates
SET aff_rebate_rate_percent = $1::numeric, updated_at = NOW()
WHERE user_id = ANY($2)
",
    )
    .bind(rate.map(decimal_string))
    .bind(&user_ids)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(Envelope::success(
        serde_json::json!({"affected": user_ids.len()}),
    )))
}

async fn user_overview(
    State(state): State<AdminApiState>,
    Path(user_id): Path<i64>,
) -> Result<Json<Envelope<AffiliateUserOverview>>, AdminError> {
    validate_user_id(user_id)?;
    let row = sqlx::query(
        r"
SELECT affiliate.user_id, COALESCE(u.email, '') AS email,
       COALESCE(u.username, '') AS username, affiliate.aff_code,
       affiliate.aff_rebate_rate_percent::double precision AS custom_rate,
       affiliate.aff_count,
       COALESCE(rebated.invitee_count, 0)::integer AS rebated_invitee_count,
       (affiliate.aff_quota + COALESCE(matured.amount, 0))::double precision AS available_quota,
       affiliate.aff_history_quota::double precision AS history_quota
FROM user_affiliates affiliate
JOIN users u ON u.id = affiliate.user_id AND u.deleted_at IS NULL
LEFT JOIN (
    SELECT user_id, COUNT(DISTINCT source_user_id) AS invitee_count
    FROM user_affiliate_ledger
    WHERE action = 'accrue' AND source_user_id IS NOT NULL
    GROUP BY user_id
) rebated ON rebated.user_id = affiliate.user_id
LEFT JOIN (
    SELECT user_id, SUM(amount) AS amount
    FROM user_affiliate_ledger
    WHERE action = 'accrue' AND frozen_until IS NOT NULL AND frozen_until <= NOW()
    GROUP BY user_id
) matured ON matured.user_id = affiliate.user_id
WHERE affiliate.user_id = $1
",
    )
    .bind(user_id)
    .fetch_optional(state.service.pool())
    .await?
    .ok_or(AdminError::NotFound("affiliate profile"))?;
    let custom_rate: Option<f64> = row.try_get("custom_rate")?;
    let rate = match custom_rate {
        Some(rate) => rate,
        None => global_rebate_rate(&state).await?,
    }
    .clamp(0.0, 100.0);
    Ok(Json(Envelope::success(AffiliateUserOverview {
        user_id: row.try_get("user_id")?,
        email: row.try_get("email")?,
        username: row.try_get("username")?,
        aff_code: row.try_get("aff_code")?,
        rebate_rate_percent: rate,
        invited_count: row.try_get("aff_count")?,
        rebated_invitee_count: row.try_get("rebated_invitee_count")?,
        available_quota: row.try_get("available_quota")?,
        history_quota: row.try_get("history_quota")?,
    })))
}

async fn list_invites(
    State(state): State<AdminApiState>,
    Query(query): Query<AffiliateQuery>,
) -> Result<Json<Envelope<Page<InviteRecord>>>, AdminError> {
    let query = query.normalized();
    let base = r"
FROM user_affiliates affiliate
JOIN users invitee ON invitee.id = affiliate.user_id
JOIN users inviter ON inviter.id = affiliate.inviter_id
JOIN user_affiliates inviter_affiliate ON inviter_affiliate.user_id = affiliate.inviter_id
";
    let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) ");
    count.push(base);
    push_record_filter(
        &mut count,
        &query,
        "affiliate.created_at",
        "CONCAT_WS(' ', inviter.email, inviter.username, invitee.email, invitee.username, affiliate.inviter_id::text, affiliate.user_id::text, inviter_affiliate.aff_code)",
        false,
    );
    let total = count
        .build_query_scalar::<i64>()
        .fetch_one(state.service.pool())
        .await?;

    let mut list = QueryBuilder::<Postgres>::new(
        r#"
SELECT affiliate.inviter_id, COALESCE(inviter.email, '') AS inviter_email,
       COALESCE(inviter.username, '') AS inviter_username,
       affiliate.user_id AS invitee_id, COALESCE(invitee.email, '') AS invitee_email,
       COALESCE(invitee.username, '') AS invitee_username,
       COALESCE(inviter_affiliate.aff_code, '') AS aff_code,
       COALESCE(SUM(ledger.amount), 0)::double precision AS total_rebate,
       to_char(affiliate.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
"#,
    );
    list.push(base).push(
        r"
LEFT JOIN user_affiliate_ledger ledger
       ON ledger.user_id = affiliate.inviter_id
      AND ledger.source_user_id = affiliate.user_id
      AND ledger.action = 'accrue'
",
    );
    push_record_filter(
        &mut list,
        &query,
        "affiliate.created_at",
        "CONCAT_WS(' ', inviter.email, inviter.username, invitee.email, invitee.username, affiliate.inviter_id::text, affiliate.user_id::text, inviter_affiliate.aff_code)",
        false,
    );
    list.push(
        " GROUP BY affiliate.inviter_id, inviter.email, inviter.username, affiliate.user_id, invitee.email, invitee.username, inviter_affiliate.aff_code, affiliate.created_at ",
    );
    push_order(
        &mut list,
        invite_sort_column(&query.sort_by),
        query.descending(),
    );
    list.push(" LIMIT ")
        .push_bind(query.page_size)
        .push(" OFFSET ")
        .push_bind(query.offset());
    let rows = list.build().fetch_all(state.service.pool()).await?;
    let items = rows
        .iter()
        .map(invite_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Envelope::success(query.page(items, total))))
}

async fn list_rebates(
    State(state): State<AdminApiState>,
    Query(query): Query<AffiliateQuery>,
) -> Result<Json<Envelope<Page<RebateRecord>>>, AdminError> {
    let query = query.normalized();
    let base = r"
FROM user_affiliate_ledger ledger
JOIN payment_orders orders ON orders.id = ledger.source_order_id
JOIN users invitee ON invitee.id = ledger.source_user_id
JOIN users inviter ON inviter.id = ledger.user_id
WHERE ledger.action = 'accrue' AND ledger.source_order_id IS NOT NULL
";
    let search = "CONCAT_WS(' ', inviter.email, inviter.username, invitee.email, invitee.username, orders.id::text, orders.out_trade_no, orders.payment_type, orders.status)";
    let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) ");
    count.push(base);
    push_record_filter(&mut count, &query, "ledger.created_at", search, true);
    let total = count
        .build_query_scalar::<i64>()
        .fetch_one(state.service.pool())
        .await?;
    let mut list = QueryBuilder::<Postgres>::new(
        r#"
SELECT orders.id AS order_id, orders.out_trade_no, ledger.user_id AS inviter_id,
       COALESCE(inviter.email, '') AS inviter_email,
       COALESCE(inviter.username, '') AS inviter_username,
       ledger.source_user_id AS invitee_id, COALESCE(invitee.email, '') AS invitee_email,
       COALESCE(invitee.username, '') AS invitee_username,
       orders.amount::double precision AS order_amount,
       orders.pay_amount::double precision AS pay_amount,
       ledger.amount::double precision AS rebate_amount,
       orders.payment_type, orders.status AS order_status,
       to_char(ledger.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
"#,
    );
    list.push(base);
    push_record_filter(&mut list, &query, "ledger.created_at", search, true);
    push_order(
        &mut list,
        rebate_sort_column(&query.sort_by),
        query.descending(),
    );
    list.push(" LIMIT ")
        .push_bind(query.page_size)
        .push(" OFFSET ")
        .push_bind(query.offset());
    let rows = list.build().fetch_all(state.service.pool()).await?;
    let items = rows
        .iter()
        .map(rebate_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Envelope::success(query.page(items, total))))
}

async fn list_transfers(
    State(state): State<AdminApiState>,
    Query(query): Query<AffiliateQuery>,
) -> Result<Json<Envelope<Page<TransferRecord>>>, AdminError> {
    let query = query.normalized();
    let base = r"
FROM user_affiliate_ledger ledger
JOIN users u ON u.id = ledger.user_id
WHERE ledger.action = 'transfer'
";
    let search = "CONCAT_WS(' ', u.email, u.username, u.id::text)";
    let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) ");
    count.push(base);
    push_record_filter(&mut count, &query, "ledger.created_at", search, true);
    let total = count
        .build_query_scalar::<i64>()
        .fetch_one(state.service.pool())
        .await?;
    let mut list = QueryBuilder::<Postgres>::new(
        r#"
SELECT ledger.id AS ledger_id, ledger.user_id, COALESCE(u.email, '') AS user_email,
       COALESCE(u.username, '') AS username, ledger.amount::double precision AS amount,
       ledger.balance_after::double precision AS balance_after,
       ledger.aff_quota_after::double precision AS available_quota_after,
       ledger.aff_frozen_quota_after::double precision AS frozen_quota_after,
       ledger.aff_history_quota_after::double precision AS history_quota_after,
       to_char(ledger.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
"#,
    );
    list.push(base);
    push_record_filter(&mut list, &query, "ledger.created_at", search, true);
    push_order(
        &mut list,
        transfer_sort_column(&query.sort_by),
        query.descending(),
    );
    list.push(" LIMIT ")
        .push_bind(query.page_size)
        .push(" OFFSET ")
        .push_bind(query.offset());
    let rows = list.build().fetch_all(state.service.pool()).await?;
    let items = rows
        .iter()
        .map(transfer_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Envelope::success(query.page(items, total))))
}

fn push_record_filter(
    builder: &mut QueryBuilder<'_, Postgres>,
    query: &AffiliateQuery,
    time_column: &'static str,
    search_expression: &'static str,
    already_has_where: bool,
) {
    let mut has_clause = already_has_where;
    for (value, operator) in [(query.start_time(), ">="), (query.end_time(), "<=")] {
        if let Some(value) = value {
            push_filter_prefix(builder, &mut has_clause);
            builder
                .push(time_column)
                .push(" ")
                .push(operator)
                .push(" ")
                .push_bind(value)
                .push("::timestamptz");
        }
    }
    if !query.search.is_empty() {
        push_filter_prefix(builder, &mut has_clause);
        builder
            .push("LOWER(")
            .push(search_expression)
            .push(") LIKE ")
            .push_bind(format!("%{}%", query.search.to_ascii_lowercase()));
    }
}

fn push_filter_prefix(builder: &mut QueryBuilder<'_, Postgres>, has_clause: &mut bool) {
    if *has_clause {
        builder.push(" AND ");
    } else {
        builder.push(" WHERE ");
        *has_clause = true;
    }
}

fn push_order(builder: &mut QueryBuilder<'_, Postgres>, column: &'static str, descending: bool) {
    builder
        .push(" ORDER BY ")
        .push(column)
        .push(if descending { " DESC" } else { " ASC" })
        .push(" NULLS LAST");
}

fn invite_sort_column(sort_by: &str) -> &'static str {
    match sort_by {
        "inviter" => "inviter.email",
        "invitee" => "invitee.email",
        "aff_code" => "inviter_affiliate.aff_code",
        "total_rebate" => "total_rebate",
        _ => "affiliate.created_at",
    }
}

fn rebate_sort_column(sort_by: &str) -> &'static str {
    match sort_by {
        "order" => "orders.id",
        "inviter" => "inviter.email",
        "invitee" => "invitee.email",
        "order_amount" => "orders.amount",
        "pay_amount" => "orders.pay_amount",
        "rebate_amount" => "ledger.amount",
        "payment_type" => "orders.payment_type",
        "order_status" => "orders.status",
        _ => "ledger.created_at",
    }
}

fn transfer_sort_column(sort_by: &str) -> &'static str {
    match sort_by {
        "user" => "u.email",
        "amount" => "ledger.amount",
        "balance_after" => "ledger.balance_after",
        "available_quota_after" => "ledger.aff_quota_after",
        "frozen_quota_after" => "ledger.aff_frozen_quota_after",
        "history_quota_after" => "ledger.aff_history_quota_after",
        _ => "ledger.created_at",
    }
}

async fn ensure_affiliate(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), AdminError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !exists {
        return Err(AdminError::NotFound("user"));
    }
    for _ in 0..12 {
        let code = random_affiliate_code();
        let result = sqlx::query(
            r"
INSERT INTO user_affiliates (user_id, aff_code, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (user_id) DO NOTHING
",
        )
        .bind(user_id)
        .bind(code)
        .execute(&mut **transaction)
        .await;
        match result {
            Ok(_) => return Ok(()),
            Err(error) if is_unique_violation(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(AdminError::Unavailable(
        "could not allocate a unique affiliate code".to_owned(),
    ))
}

async fn set_rebate_rate(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    rate: Option<f64>,
) -> Result<(), AdminError> {
    sqlx::query(
        r"
UPDATE user_affiliates
SET aff_rebate_rate_percent = $2::numeric, updated_at = NOW()
WHERE user_id = $1
",
    )
    .bind(user_id)
    .bind(rate.map(decimal_string))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn reset_affiliate_settings(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), AdminError> {
    for _ in 0..12 {
        let result = sqlx::query(
            r"
UPDATE user_affiliates
SET aff_code = $2, aff_code_custom = FALSE,
    aff_rebate_rate_percent = NULL, updated_at = NOW()
WHERE user_id = $1
",
        )
        .bind(user_id)
        .bind(random_affiliate_code())
        .execute(&mut **transaction)
        .await;
        match result {
            Ok(done) if done.rows_affected() == 1 => return Ok(()),
            Ok(_) => return Err(AdminError::NotFound("affiliate profile")),
            Err(error) if is_unique_violation(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(AdminError::Unavailable(
        "could not allocate a unique affiliate code".to_owned(),
    ))
}

async fn global_rebate_rate(state: &AdminApiState) -> Result<f64, AdminError> {
    let raw = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'affiliate_rebate_rate' LIMIT 1",
    )
    .fetch_optional(state.service.pool())
    .await?;
    Ok(raw
        .as_deref()
        .and_then(parse_setting_number)
        .unwrap_or(DEFAULT_REBATE_RATE_PERCENT))
}

fn parse_setting_number(raw: &str) -> Option<f64> {
    raw.trim().parse::<f64>().ok().or_else(|| {
        serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|value| value.as_f64())
    })
}

fn validate_user_id(user_id: i64) -> Result<(), AdminError> {
    if user_id > 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest("Invalid user_id".to_owned()))
    }
}

fn normalize_affiliate_code(raw: &str) -> Result<String, AdminError> {
    let code = raw.trim().to_ascii_uppercase();
    if (4..=32).contains(&code.len())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        Ok(code)
    } else {
        Err(AdminError::BadRequest("invalid affiliate code".to_owned()))
    }
}

fn validate_rebate_rate(rate: Option<f64>) -> Result<(), AdminError> {
    if rate.is_none_or(|value| value.is_finite() && (0.0..=100.0).contains(&value)) {
        Ok(())
    } else {
        Err(AdminError::BadRequest("invalid rebate rate".to_owned()))
    }
}

fn affiliate_write_error(error: sqlx::Error) -> AdminError {
    if is_unique_violation(&error) {
        AdminError::Conflict("affiliate code already in use".to_owned())
    } else {
        error.into()
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.code().as_deref() == Some("23505"))
}

fn random_affiliate_code() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase()
}

fn decimal_string(value: f64) -> String {
    value.to_string()
}

fn normalize_filter_time(raw: &str, end_of_day: bool) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(value) = DateTime::parse_from_rfc3339(raw) {
        return Some(value.to_rfc3339());
    }
    let date = NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()?;
    let date = if end_of_day {
        date.checked_add_days(Days::new(1))?
    } else {
        date
    };
    let timestamp = date.and_hms_opt(0, 0, 0)?.and_utc();
    if end_of_day {
        timestamp
            .checked_sub_signed(chrono::Duration::microseconds(1))
            .map(|value| value.to_rfc3339())
    } else {
        Some(timestamp.to_rfc3339())
    }
}

fn affiliate_admin_entry_from_row(row: &PgRow) -> Result<AffiliateAdminEntry, sqlx::Error> {
    Ok(AffiliateAdminEntry {
        user_id: row.try_get("user_id")?,
        email: row.try_get("email")?,
        username: row.try_get("username")?,
        aff_code: row.try_get("aff_code")?,
        aff_code_custom: row.try_get("aff_code_custom")?,
        aff_rebate_rate_percent: row.try_get("rate")?,
        aff_count: row.try_get("aff_count")?,
    })
}

fn invite_from_row(row: &PgRow) -> Result<InviteRecord, sqlx::Error> {
    Ok(InviteRecord {
        inviter_id: row.try_get("inviter_id")?,
        inviter_email: row.try_get("inviter_email")?,
        inviter_username: row.try_get("inviter_username")?,
        invitee_id: row.try_get("invitee_id")?,
        invitee_email: row.try_get("invitee_email")?,
        invitee_username: row.try_get("invitee_username")?,
        aff_code: row.try_get("aff_code")?,
        total_rebate: row.try_get("total_rebate")?,
        created_at: row.try_get("created_at")?,
    })
}

fn rebate_from_row(row: &PgRow) -> Result<RebateRecord, sqlx::Error> {
    Ok(RebateRecord {
        order_id: row.try_get("order_id")?,
        out_trade_no: row.try_get("out_trade_no")?,
        inviter_id: row.try_get("inviter_id")?,
        inviter_email: row.try_get("inviter_email")?,
        inviter_username: row.try_get("inviter_username")?,
        invitee_id: row.try_get("invitee_id")?,
        invitee_email: row.try_get("invitee_email")?,
        invitee_username: row.try_get("invitee_username")?,
        order_amount: row.try_get("order_amount")?,
        pay_amount: row.try_get("pay_amount")?,
        rebate_amount: row.try_get("rebate_amount")?,
        payment_type: row.try_get("payment_type")?,
        order_status: row.try_get("order_status")?,
        created_at: row.try_get("created_at")?,
    })
}

fn transfer_from_row(row: &PgRow) -> Result<TransferRecord, sqlx::Error> {
    let balance_after = row.try_get("balance_after")?;
    let available_quota_after = row.try_get("available_quota_after")?;
    let frozen_quota_after = row.try_get("frozen_quota_after")?;
    let history_quota_after = row.try_get("history_quota_after")?;
    Ok(TransferRecord {
        ledger_id: row.try_get("ledger_id")?,
        user_id: row.try_get("user_id")?,
        user_email: row.try_get("user_email")?,
        username: row.try_get("username")?,
        amount: row.try_get("amount")?,
        balance_after,
        available_quota_after,
        frozen_quota_after,
        history_quota_after,
        snapshot_available: balance_after.is_some()
            && available_quota_after.is_some()
            && frozen_quota_after.is_some()
            && history_quota_after.is_some(),
        created_at: row.try_get("created_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affiliate_mutation_inputs_are_fail_closed() {
        assert_eq!(
            normalize_affiliate_code(" vip-2026 ").ok().as_deref(),
            Some("VIP-2026")
        );
        assert!(normalize_affiliate_code("bad code").is_err());
        assert!(normalize_affiliate_code("abc").is_err());
        assert!(validate_rebate_rate(Some(0.0)).is_ok());
        assert!(validate_rebate_rate(Some(100.0)).is_ok());
        assert!(validate_rebate_rate(Some(f64::NAN)).is_err());
        assert!(validate_rebate_rate(Some(100.01)).is_err());
    }

    #[test]
    fn record_filters_and_sorting_are_bounded() {
        let query = AffiliateQuery {
            page: -1,
            page_size: 1_000,
            search: " test ".to_owned(),
            start_at: "2026-01-01".to_owned(),
            end_at: "2026-01-02".to_owned(),
            sort_by: "DROP TABLE users".to_owned(),
            sort_order: "asc".to_owned(),
            _timezone: String::new(),
        }
        .normalized();
        assert_eq!(query.page, 1);
        assert_eq!(query.page_size, MAX_PAGE_SIZE);
        assert_eq!(query.search, "test");
        assert_eq!(invite_sort_column(&query.sort_by), "affiliate.created_at");
        assert!(!query.descending());
        assert!(query.start_time().is_some());
        assert!(query.end_time().is_some());
    }
}
