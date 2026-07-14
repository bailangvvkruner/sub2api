use std::collections::{BTreeMap, HashSet};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use serde::Serialize;
use sqlx::{Row, postgres::PgRow};

use super::{authenticated_user, decimal, optional_decimal};
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState, UserView};

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/groups/available", get(available_groups))
        .route("/api/v1/groups/rates", get(group_rates))
}

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct GroupView {
    pub(super) id: i64,
    pub(super) name: String,
    description: String,
    platform: String,
    rate_multiplier: f64,
    is_exclusive: bool,
    status: String,
    subscription_type: String,
    pub(super) daily_limit_usd: Option<f64>,
    pub(super) weekly_limit_usd: Option<f64>,
    pub(super) monthly_limit_usd: Option<f64>,
    allow_image_generation: bool,
    allow_batch_image_generation: bool,
    image_rate_independent: bool,
    image_rate_multiplier: f64,
    batch_image_discount_multiplier: f64,
    batch_image_hold_multiplier: f64,
    video_rate_independent: bool,
    video_rate_multiplier: f64,
    peak_rate_enabled: bool,
    peak_start: String,
    peak_end: String,
    peak_rate_multiplier: f64,
    image_price_1k: Option<f64>,
    image_price_2k: Option<f64>,
    image_price_4k: Option<f64>,
    video_price_480p: Option<f64>,
    video_price_720p: Option<f64>,
    video_price_1080p: Option<f64>,
    claude_code_only: bool,
    fallback_group_id: Option<i64>,
    fallback_group_id_on_invalid_request: Option<i64>,
    allow_messages_dispatch: bool,
    require_oauth_only: bool,
    require_privacy_set: bool,
    rpm_limit: i32,
    created_at: String,
    updated_at: String,
}

pub(super) const GROUP_SELECT: &str = r#"
SELECT
    g.id, g.name, COALESCE(g.description, '') AS description,
    g.platform, g.rate_multiplier::text AS rate_multiplier,
    g.is_exclusive, g.status, g.subscription_type,
    g.daily_limit_usd::text AS daily_limit_usd,
    g.weekly_limit_usd::text AS weekly_limit_usd,
    g.monthly_limit_usd::text AS monthly_limit_usd,
    g.allow_image_generation, g.allow_batch_image_generation,
    g.image_rate_independent,
    g.image_rate_multiplier::text AS image_rate_multiplier,
    g.batch_image_discount_multiplier::text AS batch_image_discount_multiplier,
    g.batch_image_hold_multiplier::text AS batch_image_hold_multiplier,
    g.video_rate_independent,
    g.video_rate_multiplier::text AS video_rate_multiplier,
    g.peak_rate_enabled, g.peak_start, g.peak_end,
    g.peak_rate_multiplier::text AS peak_rate_multiplier,
    g.image_price_1k::text AS image_price_1k,
    g.image_price_2k::text AS image_price_2k,
    g.image_price_4k::text AS image_price_4k,
    g.video_price_480p::text AS video_price_480p,
    g.video_price_720p::text AS video_price_720p,
    g.video_price_1080p::text AS video_price_1080p,
    g.claude_code_only, g.fallback_group_id,
    g.fallback_group_id_on_invalid_request,
    g.allow_messages_dispatch, g.require_oauth_only, g.require_privacy_set,
    g.rpm_limit,
    to_char(g.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(g.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
FROM groups g
"#;

async fn available_groups(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<GroupView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let visible_ids = available_group_ids(&state, &user).await?;
    let sql = format!(
        "{GROUP_SELECT} WHERE g.status = 'active' AND g.deleted_at IS NULL \
         ORDER BY g.sort_order ASC, g.id ASC"
    );
    let rows = sqlx::query(&sql).fetch_all(state.pool()).await?;
    let groups = rows
        .iter()
        .filter(|row| {
            row.try_get::<i64, _>("id")
                .is_ok_and(|id| visible_ids.contains(&id))
        })
        .map(group_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ApiEnvelope::success(groups)))
}

pub(super) async fn available_group_ids(
    state: &ControlApiState,
    user: &UserView,
) -> Result<HashSet<i64>, ApiError> {
    let subscribed = sqlx::query_scalar::<_, i64>(
        r"
SELECT group_id
FROM user_subscriptions
WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
  AND deleted_at IS NULL
",
    )
    .bind(user.id)
    .fetch_all(state.pool())
    .await?
    .into_iter()
    .collect::<HashSet<_>>();
    let allowed = user.allowed_groups.iter().copied().collect::<HashSet<_>>();
    let rows = sqlx::query(
        r"
SELECT id, subscription_type, is_exclusive
FROM groups
WHERE status = 'active' AND deleted_at IS NULL
",
    )
    .fetch_all(state.pool())
    .await?;
    let visible = rows
        .iter()
        .filter_map(|row| {
            let id = row.try_get::<i64, _>("id").ok()?;
            let subscription_type = row.try_get::<String, _>("subscription_type").ok()?;
            let is_exclusive = row.try_get::<bool, _>("is_exclusive").ok()?;
            let visible = if subscription_type == "subscription" {
                subscribed.contains(&id)
            } else {
                !is_exclusive || allowed.contains(&id)
            };
            visible.then_some(id)
        })
        .collect::<HashSet<_>>();
    Ok(visible)
}

async fn group_rates(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<BTreeMap<i64, f64>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let rows = sqlx::query(
        r"
SELECT group_id, rate_multiplier::text AS rate_multiplier
FROM user_group_rate_multipliers
WHERE user_id = $1
ORDER BY group_id
",
    )
    .bind(user.id)
    .fetch_all(state.pool())
    .await?;
    let rates = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get("group_id")?,
                decimal(row.try_get::<String, _>("rate_multiplier")?.as_str())?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, sqlx::Error>>()?;
    Ok(Json(ApiEnvelope::success(rates)))
}

pub(super) fn group_from_row(row: &PgRow) -> Result<GroupView, sqlx::Error> {
    Ok(GroupView {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        platform: row.try_get("platform")?,
        rate_multiplier: decimal(row.try_get::<String, _>("rate_multiplier")?.as_str())?,
        is_exclusive: row.try_get("is_exclusive")?,
        status: row.try_get("status")?,
        subscription_type: row.try_get("subscription_type")?,
        daily_limit_usd: optional_decimal(row.try_get("daily_limit_usd")?)?,
        weekly_limit_usd: optional_decimal(row.try_get("weekly_limit_usd")?)?,
        monthly_limit_usd: optional_decimal(row.try_get("monthly_limit_usd")?)?,
        allow_image_generation: row.try_get("allow_image_generation")?,
        allow_batch_image_generation: row.try_get("allow_batch_image_generation")?,
        image_rate_independent: row.try_get("image_rate_independent")?,
        image_rate_multiplier: decimal(
            row.try_get::<String, _>("image_rate_multiplier")?.as_str(),
        )?,
        batch_image_discount_multiplier: decimal(
            row.try_get::<String, _>("batch_image_discount_multiplier")?
                .as_str(),
        )?,
        batch_image_hold_multiplier: decimal(
            row.try_get::<String, _>("batch_image_hold_multiplier")?
                .as_str(),
        )?,
        video_rate_independent: row.try_get("video_rate_independent")?,
        video_rate_multiplier: decimal(
            row.try_get::<String, _>("video_rate_multiplier")?.as_str(),
        )?,
        peak_rate_enabled: row.try_get("peak_rate_enabled")?,
        peak_start: row.try_get("peak_start")?,
        peak_end: row.try_get("peak_end")?,
        peak_rate_multiplier: decimal(row.try_get::<String, _>("peak_rate_multiplier")?.as_str())?,
        image_price_1k: optional_decimal(row.try_get("image_price_1k")?)?,
        image_price_2k: optional_decimal(row.try_get("image_price_2k")?)?,
        image_price_4k: optional_decimal(row.try_get("image_price_4k")?)?,
        video_price_480p: optional_decimal(row.try_get("video_price_480p")?)?,
        video_price_720p: optional_decimal(row.try_get("video_price_720p")?)?,
        video_price_1080p: optional_decimal(row.try_get("video_price_1080p")?)?,
        claude_code_only: row.try_get("claude_code_only")?,
        fallback_group_id: row.try_get("fallback_group_id")?,
        fallback_group_id_on_invalid_request: row
            .try_get("fallback_group_id_on_invalid_request")?,
        allow_messages_dispatch: row.try_get("allow_messages_dispatch")?,
        require_oauth_only: row.try_get("require_oauth_only")?,
        require_privacy_set: row.try_get("require_privacy_set")?,
        rpm_limit: row.try_get("rpm_limit")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
