//! Domain-shaped administrator relation queries.

use std::collections::BTreeMap;

use serde_json::{Number, Value, json};
use sqlx::PgPool;

use super::{AdminError, AdminRuntimeStatsProvider, AdminService, compat::required_path_id};

const MAX_PAGE_SIZE: i64 = 1_000;
const RELATION_HANDLERS: [&str; 8] = [
    "h.Admin.Group.GetGroupAPIKeys",
    "h.Admin.User.GetUserAPIKeys",
    "h.Admin.Subscription.ListByGroup",
    "h.Admin.Subscription.ListByUser",
    "h.Admin.Promo.GetUsages",
    "h.Admin.ScheduledTest.ListResults",
    "h.Admin.ScheduledTest.ListByAccount",
    "h.Admin.Group.GetGroupRateMultipliers",
];

const USER_DTO_JSON: &str = r"
(to_jsonb(relation_user) - ARRAY[
    'password_hash','notes','last_used_at','deleted_at','wechat','totp_secret',
    'totp_enabled','auth_generation','api_key_encrypted'
]::text[])
|| jsonb_build_object(
    'allowed_groups', COALESCE((
        SELECT jsonb_agg(allowed.group_id ORDER BY allowed.group_id)
        FROM user_allowed_groups allowed
        WHERE allowed.user_id = relation_user.id
    ), '[]'::jsonb),
    'balance_notify_extra_emails', COALESCE(
        NULLIF(relation_user.balance_notify_extra_emails, ''), '[]'
    )::jsonb
)
";

const GROUP_DTO_JSON: &str = r"
to_jsonb(relation_group) - ARRAY[
    'deleted_at','model_routing','model_routing_enabled','mcp_xml_inject',
    'default_mapped_model','messages_dispatch_model_config','models_list_config',
    'supported_model_scopes','sort_order','default_validity_days'
]::text[]
";

const SUBSCRIPTION_DTO_JSON: &str = r"
(to_jsonb(subscription) - 'deleted_at')
|| jsonb_build_object(
    'status', CASE
        WHEN subscription.status = 'active' AND subscription.expires_at <= NOW() THEN 'expired'
        ELSE subscription.status
    END,
    'notes', COALESCE(subscription.notes, ''),
    'daily_window_start', CASE
        WHEN subscription.daily_window_start IS NOT NULL
         AND subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
         AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
        THEN NULL ELSE subscription.daily_window_start END,
    'daily_usage_usd', CASE
        WHEN subscription.daily_window_start IS NOT NULL
         AND subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
         AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
        THEN 0 ELSE subscription.daily_usage_usd END,
    'weekly_window_start', CASE
        WHEN subscription.weekly_window_start IS NOT NULL
         AND subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
        THEN NULL ELSE subscription.weekly_window_start END,
    'weekly_usage_usd', CASE
        WHEN subscription.weekly_window_start IS NOT NULL
         AND subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
        THEN 0 ELSE subscription.weekly_usage_usd END,
    'monthly_window_start', CASE
        WHEN subscription.monthly_window_start IS NOT NULL
         AND subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
        THEN NULL ELSE subscription.monthly_window_start END,
    'monthly_usage_usd', CASE
        WHEN subscription.monthly_window_start IS NOT NULL
         AND subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
        THEN 0 ELSE subscription.monthly_usage_usd END
)
";

pub(super) async fn dispatch(
    service: &AdminService,
    handler: &str,
    path: &str,
    query: &BTreeMap<String, String>,
) -> Option<Result<Value, AdminError>> {
    if !RELATION_HANDLERS.contains(&handler) {
        return None;
    }
    let pool = service.pool();
    let runtime = service.runtime_stats();
    let result = match handler {
        "h.Admin.Group.GetGroupAPIKeys" => {
            list_api_keys(
                pool,
                runtime,
                RelationOwner::Group,
                required_path_id(path, "group").ok()?,
                query,
            )
            .await
        }
        "h.Admin.User.GetUserAPIKeys" => {
            list_api_keys(
                pool,
                runtime,
                RelationOwner::User,
                required_path_id(path, "user").ok()?,
                query,
            )
            .await
        }
        "h.Admin.Subscription.ListByGroup" => {
            list_group_subscriptions(pool, runtime, required_path_id(path, "group").ok()?, query)
                .await
        }
        "h.Admin.Subscription.ListByUser" => {
            list_user_subscriptions(pool, runtime, required_path_id(path, "user").ok()?).await
        }
        "h.Admin.Promo.GetUsages" => {
            list_promo_usages(pool, required_path_id(path, "promo code").ok()?, query).await
        }
        "h.Admin.ScheduledTest.ListResults" => {
            list_scheduled_results(
                pool,
                required_path_id(path, "scheduled test plan").ok()?,
                query,
            )
            .await
        }
        "h.Admin.ScheduledTest.ListByAccount" => {
            list_scheduled_plans(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Group.GetGroupRateMultipliers" => {
            list_group_rate_multipliers(pool, required_path_id(path, "group").ok()?).await
        }
        _ => unreachable!("RELATION_HANDLERS and relation dispatch must stay aligned"),
    };
    Some(result)
}

#[derive(Clone, Copy)]
enum RelationOwner {
    User,
    Group,
}

async fn list_api_keys(
    pool: &PgPool,
    runtime: Option<&dyn AdminRuntimeStatsProvider>,
    owner: RelationOwner,
    id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let (page, page_size) = pagination(query);
    let (foreign_key, default_order, relation_json, last_ip) = match owner {
        RelationOwner::User => (
            "user_id",
            "api_key.created_at",
            format!(
                "CASE WHEN relation_group.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object('group', ({GROUP_DTO_JSON})) END"
            ),
            "latest_ip.ip_address",
        ),
        RelationOwner::Group => (
            "group_id",
            "api_key.id",
            format!(
                "CASE WHEN relation_user.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object('user', ({USER_DTO_JSON})) END"
            ),
            "NULL::text",
        ),
    };
    let sort_column = match query.get("sort_by").map(String::as_str) {
        Some("name") => "api_key.name",
        Some("status") => "api_key.status",
        Some("expires_at") => "api_key.expires_at",
        Some("last_used_at") => "api_key.last_used_at",
        Some("id") => "api_key.id",
        Some("created_at") => "api_key.created_at",
        _ => default_order,
    };
    let direction = if query
        .get("sort_order")
        .is_some_and(|value| value.eq_ignore_ascii_case("asc"))
    {
        "ASC"
    } else {
        "DESC"
    };
    let sql = format!(
        r"
SELECT (to_jsonb(api_key) - 'deleted_at')
|| jsonb_build_object(
    'ip_whitelist', COALESCE(api_key.ip_whitelist, '[]'::jsonb),
    'ip_blacklist', COALESCE(api_key.ip_blacklist, '[]'::jsonb),
    'last_used_ip', {last_ip},
    'current_concurrency', 0,
    'usage_5h', CASE WHEN api_key.window_5h_start IS NULL OR api_key.window_5h_start + INTERVAL '5 hours' <= NOW() THEN 0 ELSE api_key.usage_5h END,
    'usage_1d', CASE WHEN api_key.window_1d_start IS NULL OR api_key.window_1d_start + INTERVAL '1 day' <= NOW() THEN 0 ELSE api_key.usage_1d END,
    'usage_7d', CASE WHEN api_key.window_7d_start IS NULL OR api_key.window_7d_start + INTERVAL '7 days' <= NOW() THEN 0 ELSE api_key.usage_7d END,
    'reset_5h_at', CASE WHEN api_key.window_5h_start + INTERVAL '5 hours' > NOW() THEN api_key.window_5h_start + INTERVAL '5 hours' END,
    'reset_1d_at', CASE WHEN api_key.window_1d_start + INTERVAL '1 day' > NOW() THEN api_key.window_1d_start + INTERVAL '1 day' END,
    'reset_7d_at', CASE WHEN api_key.window_7d_start + INTERVAL '7 days' > NOW() THEN api_key.window_7d_start + INTERVAL '7 days' END
)
|| ({relation_json}) AS data
FROM api_keys api_key
LEFT JOIN users relation_user
       ON relation_user.id = api_key.user_id AND relation_user.deleted_at IS NULL
LEFT JOIN groups relation_group
       ON relation_group.id = api_key.group_id AND relation_group.deleted_at IS NULL
LEFT JOIN LATERAL (
    SELECT usage.ip_address
    FROM usage_logs usage
    WHERE usage.api_key_id = api_key.id
      AND usage.ip_address IS NOT NULL AND usage.ip_address <> ''
    ORDER BY usage.created_at DESC, usage.id DESC
    LIMIT 1
) latest_ip ON TRUE
WHERE api_key.{foreign_key} = $1 AND api_key.deleted_at IS NULL
ORDER BY {sort_column} {direction}, api_key.id {direction}
LIMIT $2 OFFSET $3
"
    );
    let mut items = sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    for item in &mut items {
        apply_api_key_runtime(item, runtime);
    }
    let count_sql = format!(
        "SELECT COUNT(*)::bigint FROM api_keys WHERE {foreign_key} = $1 AND deleted_at IS NULL"
    );
    let total = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn list_group_subscriptions(
    pool: &PgPool,
    runtime: Option<&dyn AdminRuntimeStatsProvider>,
    group_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let (page, page_size) = pagination(query);
    let mut items = subscription_rows(
        pool,
        "subscription.group_id = $1",
        group_id,
        true,
        Some((page_size, (page - 1) * page_size)),
    )
    .await?;
    for item in &mut items {
        apply_subscription_runtime(item, runtime);
    }
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM user_subscriptions WHERE group_id = $1 AND deleted_at IS NULL",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn list_user_subscriptions(
    pool: &PgPool,
    runtime: Option<&dyn AdminRuntimeStatsProvider>,
    user_id: i64,
) -> Result<Value, AdminError> {
    let mut items =
        subscription_rows(pool, "subscription.user_id = $1", user_id, false, None).await?;
    for item in &mut items {
        apply_subscription_runtime(item, runtime);
    }
    Ok(Value::Array(items))
}

async fn list_promo_usages(
    pool: &PgPool,
    promo_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let (page, page_size) = pagination(query);
    let sql = format!(
        r"
SELECT to_jsonb(usage)
    || jsonb_build_object('user', ({USER_DTO_JSON}))
FROM promo_code_usages usage
JOIN users relation_user ON relation_user.id = usage.user_id
WHERE usage.promo_code_id = $1
ORDER BY usage.id DESC
LIMIT $2 OFFSET $3
"
    );
    let items = sqlx::query_scalar::<_, Value>(&sql)
        .bind(promo_id)
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM promo_code_usages WHERE promo_code_id = $1",
    )
    .bind(promo_id)
    .fetch_one(pool)
    .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn list_scheduled_results(
    pool: &PgPool,
    plan_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let parsed = query_i64(query, "limit", 50);
    let limit = if parsed > 0 { parsed } else { 50 };
    let items = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(result) FROM scheduled_test_results result WHERE plan_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(plan_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(items))
}

async fn list_scheduled_plans(pool: &PgPool, account_id: i64) -> Result<Value, AdminError> {
    let items = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(plan) FROM scheduled_test_plans plan WHERE account_id = $1 ORDER BY created_at DESC",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(items))
}

async fn list_group_rate_multipliers(pool: &PgPool, group_id: i64) -> Result<Value, AdminError> {
    let items = sqlx::query_scalar::<_, Value>(
        r"
SELECT jsonb_build_object(
    'user_id', rate.user_id,
    'user_name', relation_user.username,
    'user_email', relation_user.email,
    'user_notes', COALESCE(relation_user.notes, ''),
    'user_status', relation_user.status
) || CASE WHEN rate.rate_multiplier IS NULL THEN '{}'::jsonb
          ELSE jsonb_build_object('rate_multiplier', rate.rate_multiplier) END
  || CASE WHEN rate.rpm_override IS NULL THEN '{}'::jsonb
          ELSE jsonb_build_object('rpm_override', rate.rpm_override) END
FROM user_group_rate_multipliers rate
JOIN users relation_user
  ON relation_user.id = rate.user_id AND relation_user.deleted_at IS NULL
WHERE rate.group_id = $1
ORDER BY rate.user_id
",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(items))
}

async fn subscription_rows(
    pool: &PgPool,
    predicate: &str,
    owner_id: i64,
    include_user: bool,
    page: Option<(i64, i64)>,
) -> Result<Vec<Value>, AdminError> {
    let user_relation = if include_user {
        format!(
            "CASE WHEN relation_user.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object('user', ({USER_DTO_JSON})) END"
        )
    } else {
        "'{}'::jsonb".to_owned()
    };
    let limit = if page.is_some() {
        "LIMIT $2 OFFSET $3"
    } else {
        ""
    };
    let sql = format!(
        r"
SELECT ({SUBSCRIPTION_DTO_JSON})
    || CASE WHEN relation_group.id IS NULL THEN '{{}}'::jsonb
            ELSE jsonb_build_object('group', ({GROUP_DTO_JSON})) END
    || ({user_relation}) AS data
FROM user_subscriptions subscription
LEFT JOIN users relation_user
       ON relation_user.id = subscription.user_id AND relation_user.deleted_at IS NULL
LEFT JOIN groups relation_group
       ON relation_group.id = subscription.group_id AND relation_group.deleted_at IS NULL
WHERE {predicate} AND subscription.deleted_at IS NULL
ORDER BY subscription.created_at DESC
{limit}
"
    );
    let mut statement = sqlx::query_scalar::<_, Value>(&sql).bind(owner_id);
    if let Some((page_size, offset)) = page {
        statement = statement.bind(page_size).bind(offset);
    }
    Ok(statement.fetch_all(pool).await?)
}

fn apply_api_key_runtime(item: &mut Value, runtime: Option<&dyn AdminRuntimeStatsProvider>) {
    let Some(runtime) = runtime else { return };
    let Some(id) = item.get("id").and_then(Value::as_i64) else {
        return;
    };
    let pending = runtime.pending_api_key_cost(id);
    if pending.is_finite() && pending > 0.0 {
        for field in ["quota_used", "usage_5h", "usage_1d", "usage_7d"] {
            add_json_number(item, field, pending);
        }
    }
    set_json_u64(
        item,
        "current_concurrency",
        runtime.api_key_current_concurrency(id),
    );
}

fn apply_subscription_runtime(item: &mut Value, runtime: Option<&dyn AdminRuntimeStatsProvider>) {
    let Some(runtime) = runtime else { return };
    let (Some(user_id), Some(group_id)) = (
        item.get("user_id").and_then(Value::as_i64),
        item.get("group_id").and_then(Value::as_i64),
    ) else {
        return;
    };
    let pending = runtime.pending_user_group_cost(user_id, group_id);
    if pending.is_finite() && pending > 0.0 {
        for field in ["daily_usage_usd", "weekly_usage_usd", "monthly_usage_usd"] {
            add_json_number(item, field, pending);
        }
    }
}

fn add_json_number(value: &mut Value, field: &str, delta: f64) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let current = object.get(field).and_then(Value::as_f64).unwrap_or(0.0);
    if let Some(number) = Number::from_f64(current + delta) {
        object.insert(field.to_owned(), Value::Number(number));
    }
}

fn set_json_u64(value: &mut Value, field: &str, number: u64) {
    if let Some(object) = value.as_object_mut() {
        object.insert(field.to_owned(), Value::Number(Number::from(number)));
    }
}

fn pagination(query: &BTreeMap<String, String>) -> (i64, i64) {
    let page = query_i64(query, "page", 1).max(1);
    let page_size =
        query_i64(query, "page_size", query_i64(query, "limit", 20)).clamp(1, MAX_PAGE_SIZE);
    (page, page_size)
}

fn query_i64(query: &BTreeMap<String, String>, key: &str, default: i64) -> i64 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn paginated(items: &[Value], total: i64, page: i64, page_size: i64) -> Value {
    json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": ((total + page_size - 1) / page_size).max(1),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::admin_api::AdminRuntimeStatsSnapshot;

    struct RuntimeFixture;

    impl AdminRuntimeStatsProvider for RuntimeFixture {
        fn snapshot(&self) -> AdminRuntimeStatsSnapshot {
            AdminRuntimeStatsSnapshot::default()
        }

        fn pending_api_key_cost(&self, api_key_id: i64) -> f64 {
            if api_key_id == 7 { 1.25 } else { 0.0 }
        }

        fn pending_user_group_cost(&self, user_id: i64, group_id: i64) -> f64 {
            if (user_id, group_id) == (3, 4) {
                0.75
            } else {
                0.0
            }
        }

        fn api_key_current_concurrency(&self, api_key_id: i64) -> u64 {
            if api_key_id == 7 { 2 } else { 0 }
        }
    }

    #[test]
    fn dispatcher_claims_exactly_the_eight_domain_relations() {
        assert_eq!(RELATION_HANDLERS.len(), 8);
        assert_eq!(
            RELATION_HANDLERS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            RELATION_HANDLERS.len()
        );
        for handler in RELATION_HANDLERS {
            assert!(
                crate::route_contract::routes().any(|route| route.handler == handler),
                "missing Go route for {handler}"
            );
        }
    }

    #[test]
    fn pagination_matches_go_defaults_and_bounds() {
        assert_eq!(pagination(&BTreeMap::new()), (1, 20));
        assert_eq!(
            pagination(&BTreeMap::from([
                ("page".to_owned(), "3".to_owned()),
                ("limit".to_owned(), "50".to_owned()),
            ])),
            (3, 50)
        );
        assert_eq!(
            pagination(&BTreeMap::from([(
                "page_size".to_owned(),
                "5000".to_owned()
            )])),
            (1, 1_000)
        );
    }

    #[test]
    fn runtime_overlay_updates_effective_usage_without_exposing_state() {
        let runtime = RuntimeFixture;
        let mut key = json!({
            "id": 7,
            "quota_used": 2.0,
            "usage_5h": 3.0,
            "usage_1d": 4.0,
            "usage_7d": 5.0,
            "current_concurrency": 0,
        });
        apply_api_key_runtime(&mut key, Some(&runtime));
        assert_eq!(key["quota_used"], 3.25);
        assert_eq!(key["usage_5h"], 4.25);
        assert_eq!(key["usage_1d"], 5.25);
        assert_eq!(key["usage_7d"], 6.25);
        assert_eq!(key["current_concurrency"], 2);

        let mut subscription = json!({
            "user_id": 3,
            "group_id": 4,
            "daily_usage_usd": 1.0,
            "weekly_usage_usd": 2.0,
            "monthly_usage_usd": 3.0,
        });
        apply_subscription_runtime(&mut subscription, Some(&runtime));
        assert_eq!(subscription["daily_usage_usd"], 1.75);
        assert_eq!(subscription["weekly_usage_usd"], 2.75);
        assert_eq!(subscription["monthly_usage_usd"], 3.75);
    }
}
