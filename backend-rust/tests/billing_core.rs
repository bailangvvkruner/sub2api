#![allow(dead_code, unused_imports)]

#[path = "../src/runtime/mod.rs"]
mod runtime;

#[path = "../src/billing/mod.rs"]
mod billing;

use billing::{
    BillingContext, BillingEvent, BillingObserver, CostBreakdown, Decimal, PostgresBillingSink,
    PricingCatalog, PricingError, RequestType, TokenUsage, UsageProvider, parse_json_usage,
    parse_sse_usage, request_fingerprint,
};

#[test]
fn bundled_catalog_calculates_exact_gpt5_costs() {
    let catalog = PricingCatalog::bundled().expect("bundled pricing catalog should parse exactly");
    assert!(
        catalog.len() > 100,
        "the bundled catalog should contain real models"
    );

    let costs = catalog
        .calculate(
            "gpt-5",
            TokenUsage {
                input_tokens: 1_000_000,
                output_tokens: 100_000,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 2_000_000,
            },
            "1.2".parse().unwrap(),
            "0.4".parse().unwrap(),
        )
        .expect("gpt-5 has every price required by this usage");

    assert_eq!(costs.input_cost.to_string(), "1.25");
    assert_eq!(costs.output_cost.to_string(), "1");
    assert_eq!(costs.cache_read_cost.to_string(), "0.25");
    assert_eq!(costs.total_cost.to_string(), "2.5");
    assert_eq!(costs.actual_cost.to_string(), "3");
    assert_eq!(costs.account_cost.to_string(), "1");
}

#[test]
fn absent_gpt5_cache_creation_price_fails_closed() {
    let catalog = PricingCatalog::bundled().unwrap();
    let error = catalog
        .calculate(
            "gpt-5",
            TokenUsage {
                cache_creation_input_tokens: 1,
                ..TokenUsage::default()
            },
            Decimal::ONE,
            Decimal::ONE,
        )
        .unwrap_err();
    assert!(matches!(error, PricingError::MissingPrice { .. }));
}

#[test]
fn model_preflight_requires_both_base_prices() {
    let catalog = PricingCatalog::from_json(
        r#"{
            "complete": {"input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6},
            "missing_output": {"input_cost_per_token": 1e-6}
        }"#,
    )
    .unwrap();
    catalog.validate_base_prices("complete").unwrap();
    assert!(matches!(
        catalog.validate_base_prices("missing_output"),
        Err(PricingError::MissingPrice {
            category: "output",
            ..
        })
    ));
    assert!(matches!(
        catalog.validate_base_prices("unknown"),
        Err(PricingError::UnknownModel(_))
    ));
}

#[test]
fn providers_normalize_buffered_and_streaming_usage() {
    let anthropic = parse_sse_usage(
        UsageProvider::Anthropic,
        br#"data: {"type":"message_start","message":{"usage":{"input_tokens":11,"cache_creation_input_tokens":2,"cache_read_input_tokens":3}}}

data: {"type":"message_delta","usage":{"output_tokens":5}}
"#,
    )
    .unwrap();
    assert_eq!(
        anthropic,
        TokenUsage {
            input_tokens: 11,
            output_tokens: 5,
            cache_creation_input_tokens: 2,
            cache_read_input_tokens: 3,
        }
    );

    let openai = parse_json_usage(
        UsageProvider::OpenAi,
        br#"{"response":{"usage":{"input_tokens":100,"output_tokens":8,"input_tokens_details":{"cached_tokens":30,"cache_write_tokens":10}}}}"#,
    )
    .unwrap();
    assert_eq!(openai.input_tokens, 60);
    assert_eq!(openai.cache_creation_input_tokens, 10);
    assert_eq!(openai.cache_read_input_tokens, 30);

    let gemini = parse_json_usage(
        UsageProvider::Gemini,
        br#"{"response":{"usageMetadata":{"promptTokenCount":90,"cachedContentTokenCount":20,"candidatesTokenCount":6,"thoughtsTokenCount":4}}}"#,
    )
    .unwrap();
    assert_eq!(gemini.input_tokens, 70);
    assert_eq!(gemini.output_tokens, 10);
    assert_eq!(gemini.cache_read_input_tokens, 20);
}

#[test]
fn billing_event_rejects_inconsistent_financial_values() {
    let mut event = test_event("contract-request", 1, 2, 3, Some(4));
    event.validate().unwrap();
    event.costs.total_cost = Decimal::ZERO;
    assert!(event.validate().is_err());
}

#[test]
fn streaming_billing_observer_handles_arbitrary_chunk_boundaries() {
    let catalog = PricingCatalog::from_json(
        r#"{"model":{"input_cost_per_token":1e-06,"output_cost_per_token":2e-06,"cache_read_input_token_cost":5e-07}}"#,
    )
    .unwrap();
    let observer = BillingObserver::new(catalog);
    let mut stream = observer.start_sse(
        UsageProvider::OpenAi,
        BillingContext {
            request_id: "stream-request".to_owned(),
            request_fingerprint: request_fingerprint(b"request"),
            user_id: 1,
            api_key_id: 2,
            account_id: 3,
            group_id: None,
            channel_id: None,
            platform: "anthropic".to_owned(),
            model: "model".to_owned(),
            model_mapping_chain: None,
            pricing_override: None,
            group_multiplier: Decimal::ONE,
            account_multiplier: Decimal::ONE,
            stream: true,
            request_type: RequestType::Stream,
        },
    );
    stream
        .push(b"data: {\"response\":{\"usage\":{\"input_tokens\":10,\"input_tokens_details\":{\"cached_tokens\":2},\"out")
        .unwrap();
    stream
        .push(b"put_tokens\":3}}}\n\ndata: [DONE]\n\n")
        .unwrap();
    let event = stream.finish(Some(25)).unwrap();

    assert_eq!(event.usage.input_tokens, 8);
    assert_eq!(event.usage.cache_read_input_tokens, 2);
    assert_eq!(event.usage.output_tokens, 3);
    assert_eq!(event.costs.total_cost.to_string(), "0.000015");
}

#[test]
fn postgres_sink_implements_the_write_behind_contract() {
    fn assert_sink<T: runtime::BatchSink<BillingEvent>>() {}
    assert_sink::<PostgresBillingSink>();
}

fn test_event(
    request_id: &str,
    user_id: i64,
    api_key_id: i64,
    account_id: i64,
    group_id: Option<i64>,
) -> BillingEvent {
    let total = "0.5".parse::<Decimal>().unwrap();
    BillingEvent {
        request_id: request_id.to_owned(),
        request_fingerprint: request_fingerprint(b"billing-core-payload"),
        user_id,
        api_key_id,
        account_id,
        group_id,
        channel_id: None,
        platform: "anthropic".to_owned(),
        model: "billing-core-model".to_owned(),
        model_mapping_chain: None,
        billing_mode: "token".to_owned(),
        usage: TokenUsage {
            input_tokens: 100,
            output_tokens: 20,
            ..TokenUsage::default()
        },
        costs: CostBreakdown {
            input_cost: "0.4".parse().unwrap(),
            output_cost: "0.1".parse().unwrap(),
            total_cost: total,
            actual_cost: "0.75".parse().unwrap(),
            account_cost: "0.25".parse().unwrap(),
            ..CostBreakdown::default()
        },
        group_multiplier: "1.5".parse().unwrap(),
        account_multiplier: "0.5".parse().unwrap(),
        stream: false,
        request_type: RequestType::Sync,
        duration_ms: Some(12),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a fully migrated disposable PostgreSQL database"]
#[allow(clippy::too_many_lines)]
async fn postgres_batch_is_atomic_and_idempotent() {
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use uuid::Uuid;

    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for the ignored database test");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect test PostgreSQL");
    let suffix = Uuid::new_v4().simple().to_string();

    let group_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO groups (name, subscription_type) VALUES ($1, 'standard') RETURNING id",
    )
    .bind(format!("rust-billing-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let user_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (email, password_hash, balance) VALUES ($1, 'test', 10) RETURNING id",
    )
    .bind(format!("rust-billing-{suffix}@example.invalid"))
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        r"
        INSERT INTO user_platform_quotas (
            user_id, platform,
            daily_limit_usd, weekly_limit_usd, monthly_limit_usd,
            daily_usage_usd, weekly_usage_usd, monthly_usage_usd,
            daily_window_start, weekly_window_start, monthly_window_start
        )
        VALUES (
            $1, 'anthropic', 100, 100, 100,
            10, 10, 10,
            NOW() - INTERVAL '25 hours',
            NOW() - INTERVAL '8 days',
            NOW() - INTERVAL '31 days'
        )
        ",
    )
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    let account_id = sqlx::query_scalar::<_, i64>(
        r#"
        INSERT INTO accounts (name, platform, type, extra)
        VALUES (
            $1,
            'openai',
            'apikey',
            '{
                "quota_limit": 0.2,
                "quota_daily_limit": 0.2,
                "quota_daily_used": 10,
                "quota_daily_start": "2000-01-01T00:00:00Z",
                "quota_weekly_limit": 0.2,
                "quota_weekly_used": 10,
                "quota_weekly_start": "2000-01-01T00:00:00Z"
            }'::jsonb
        )
        RETURNING id
        "#,
    )
    .bind(format!("rust-billing-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let api_key_id = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO api_keys (
            user_id, key, name, group_id, quota,
            usage_5h, usage_1d, usage_7d,
            window_5h_start, window_1d_start, window_7d_start
        )
        VALUES (
            $1, $2, 'rust billing', $3, 0.5,
            10, 10, 10,
            NOW() - INTERVAL '6 hours',
            NOW() - INTERVAL '25 hours',
            NOW() - INTERVAL '8 days'
        )
        RETURNING id
        ",
    )
    .bind(user_id)
    .bind(format!("sk-{suffix}"))
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let request_id = format!("rust-{suffix}");
    let event = test_event(&request_id, user_id, api_key_id, account_id, Some(group_id));
    insert_ready_reservation(&pool, &event).await;
    let sink = PostgresBillingSink::new(pool.clone());
    sink.apply_batch(std::slice::from_ref(&event))
        .await
        .unwrap();
    sink.apply_batch(std::slice::from_ref(&event))
        .await
        .unwrap();

    let log_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM usage_logs WHERE request_id = $1 AND api_key_id = $2",
    )
    .bind(&request_id)
    .bind(api_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(log_count, 1);
    let reservation_state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM gateway_billing_reservations WHERE request_id=$1 AND api_key_id=$2",
    )
    .bind(&request_id)
    .bind(api_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reservation_state, "settled");
    let quota =
        sqlx::query_scalar::<_, String>("SELECT quota_used::text FROM api_keys WHERE id = $1")
            .bind(api_key_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(quota.parse::<Decimal>().unwrap().to_string(), "0.75");
    let key_state = sqlx::query_as::<_, (String, String, String, String, bool)>(
        r"
        SELECT status, usage_5h::text, usage_1d::text, usage_7d::text,
               window_5h_start IS NOT NULL
                   AND window_1d_start IS NOT NULL
                   AND window_7d_start IS NOT NULL
        FROM api_keys
        WHERE id = $1
        ",
    )
    .bind(api_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key_state.0, "quota_exhausted");
    for usage in [&key_state.1, &key_state.2, &key_state.3] {
        assert_eq!(usage.parse::<Decimal>().unwrap().to_string(), "0.75");
    }
    assert!(key_state.4);
    let balance = sqlx::query_scalar::<_, String>("SELECT balance::text FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(balance.parse::<Decimal>().unwrap().to_string(), "9.25");
    let platform_usage = sqlx::query_as::<_, (String, String, String, bool)>(
        r"
        SELECT daily_usage_usd::text,
               weekly_usage_usd::text,
               monthly_usage_usd::text,
               daily_window_start > NOW() - INTERVAL '1 day'
                   AND weekly_window_start > NOW() - INTERVAL '7 days'
                   AND monthly_window_start > NOW() - INTERVAL '1 minute'
        FROM user_platform_quotas
        WHERE user_id = $1 AND platform = 'anthropic' AND deleted_at IS NULL
        ",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for usage in [&platform_usage.0, &platform_usage.1, &platform_usage.2] {
        assert_eq!(usage.parse::<Decimal>().unwrap().to_string(), "0.75");
    }
    assert!(platform_usage.3);
    let account_state = sqlx::query_as::<_, (String, String, String, bool, bool)>(
        r"
        SELECT extra->>'quota_used',
               extra->>'quota_daily_used',
               extra->>'quota_weekly_used',
               extra ? 'quota_daily_start',
               extra ? 'quota_weekly_start'
        FROM accounts
        WHERE id = $1
        ",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for usage in [&account_state.0, &account_state.1, &account_state.2] {
        assert_eq!(usage.parse::<Decimal>().unwrap().to_string(), "0.25");
    }
    assert!(account_state.3 && account_state.4);
    let outbox_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM scheduler_outbox WHERE event_type = 'account_changed' AND account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(outbox_count, 1);

    let mut conflicting = event.clone();
    conflicting.request_fingerprint = request_fingerprint(b"different payload");
    assert!(sink.apply_batch(&[conflicting]).await.is_err());

    cleanup_database_rows(
        &pool,
        &request_id,
        api_key_id,
        account_id,
        user_id,
        group_id,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a fully migrated disposable PostgreSQL database"]
#[allow(clippy::too_many_lines)]
async fn postgres_subscription_billing_updates_windows_without_deducting_balance() {
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for the ignored database test");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect test PostgreSQL");
    let suffix = Uuid::new_v4().simple().to_string();
    let group_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO groups (name, subscription_type) VALUES ($1, 'subscription') RETURNING id",
    )
    .bind(format!("rust-billing-sub-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let user_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (email, password_hash, balance) VALUES ($1, 'test', 10) RETURNING id",
    )
    .bind(format!("rust-billing-sub-{suffix}@example.invalid"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let subscription_id = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO user_subscriptions (
            user_id, group_id, starts_at, expires_at, status,
            daily_window_start, weekly_window_start, monthly_window_start,
            daily_usage_usd, weekly_usage_usd, monthly_usage_usd
        )
        VALUES (
            $1, $2, NOW() - INTERVAL '1 hour', NOW() + INTERVAL '1 day', 'active',
            NOW() - INTERVAL '25 hours',
            NOW() - INTERVAL '8 days',
            NOW() - INTERVAL '31 days',
            10, 10, 10
        )
        RETURNING id
        ",
    )
    .bind(user_id)
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let account_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO accounts (name, platform, type) VALUES ($1, 'openai', 'oauth') RETURNING id",
    )
    .bind(format!("rust-billing-sub-{suffix}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    let api_key_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO api_keys (user_id, key, name, group_id) VALUES ($1, $2, 'rust subscription billing', $3) RETURNING id",
    )
    .bind(user_id)
    .bind(format!("sk-sub-{suffix}"))
    .bind(group_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let request_id = format!("rust-sub-{suffix}");
    let event = test_event(&request_id, user_id, api_key_id, account_id, Some(group_id));
    PostgresBillingSink::new(pool.clone())
        .apply_batch(&[event])
        .await
        .unwrap();

    let usages = sqlx::query_as::<_, (String, String, String)>(
        r"
        SELECT daily_usage_usd::text, weekly_usage_usd::text, monthly_usage_usd::text
        FROM user_subscriptions
        WHERE id = $1
        ",
    )
    .bind(subscription_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    for usage in [&usages.0, &usages.1, &usages.2] {
        assert_eq!(usage.parse::<Decimal>().unwrap().to_string(), "0.75");
    }
    let balance = sqlx::query_scalar::<_, String>("SELECT balance::text FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(balance.parse::<Decimal>().unwrap().to_string(), "10");
    let logged_subscription = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT subscription_id FROM usage_logs WHERE request_id = $1 AND api_key_id = $2",
    )
    .bind(&request_id)
    .bind(api_key_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(logged_subscription, Some(subscription_id));

    let _ =
        sqlx::query("DELETE FROM usage_billing_dedup WHERE request_id = $1 AND api_key_id = $2")
            .bind(&request_id)
            .bind(api_key_id)
            .execute(&pool)
            .await;
    let _ = sqlx::query("DELETE FROM usage_logs WHERE request_id = $1 AND api_key_id = $2")
        .bind(&request_id)
        .bind(api_key_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(api_key_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM user_subscriptions WHERE id = $1")
        .bind(subscription_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(&pool)
        .await;
}

async fn cleanup_database_rows(
    pool: &sqlx::PgPool,
    request_id: &str,
    api_key_id: i64,
    account_id: i64,
    user_id: i64,
    group_id: i64,
) {
    let _ = sqlx::query(
        "DELETE FROM gateway_billing_reservations WHERE request_id = $1 AND api_key_id = $2",
    )
    .bind(request_id)
    .bind(api_key_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM scheduler_outbox WHERE account_id = $1")
        .bind(account_id)
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "DELETE FROM usage_billing_dedup_archive WHERE request_id = $1 AND api_key_id = $2",
    )
    .bind(request_id)
    .bind(api_key_id)
    .execute(pool)
    .await;
    let _ =
        sqlx::query("DELETE FROM usage_billing_dedup WHERE request_id = $1 AND api_key_id = $2")
            .bind(request_id)
            .bind(api_key_id)
            .execute(pool)
            .await;
    let _ = sqlx::query("DELETE FROM usage_logs WHERE request_id = $1 AND api_key_id = $2")
        .bind(request_id)
        .bind(api_key_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(api_key_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(account_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(group_id)
        .execute(pool)
        .await;
}

async fn insert_ready_reservation(pool: &sqlx::PgPool, event: &BillingEvent) {
    sqlx::query(
        r"
        INSERT INTO gateway_billing_reservations(
            request_id,api_key_id,request_fingerprint,user_id,account_id,group_id,platform,model,state,
            input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,
            input_cost,output_cost,cache_creation_cost,cache_read_cost,total_cost,actual_cost,account_cost,
            group_multiplier,account_multiplier,stream,request_type,duration_ms,instance_id,ready_at
        ) VALUES(
            $1,$2,$3,$4,$5,$6,$7,$8,'ready',$9,$10,$11,$12,
            $13::numeric,$14::numeric,$15::numeric,$16::numeric,$17::numeric,$18::numeric,$19::numeric,
            $20::numeric,$21::numeric,$22,$23,$24,'billing-core-test',NOW()
        )
        ",
    )
    .bind(&event.request_id)
    .bind(event.api_key_id)
    .bind(&event.request_fingerprint)
    .bind(event.user_id)
    .bind(event.account_id)
    .bind(event.group_id)
    .bind(&event.platform)
    .bind(&event.model)
    .bind(i64::try_from(event.usage.input_tokens).unwrap())
    .bind(i64::try_from(event.usage.output_tokens).unwrap())
    .bind(i64::try_from(event.usage.cache_creation_input_tokens).unwrap())
    .bind(i64::try_from(event.usage.cache_read_input_tokens).unwrap())
    .bind(event.costs.input_cost.to_string())
    .bind(event.costs.output_cost.to_string())
    .bind(event.costs.cache_creation_cost.to_string())
    .bind(event.costs.cache_read_cost.to_string())
    .bind(event.costs.total_cost.to_string())
    .bind(event.costs.actual_cost.to_string())
    .bind(event.costs.account_cost.to_string())
    .bind(event.group_multiplier.to_string())
    .bind(event.account_multiplier.to_string())
    .bind(event.stream)
    .bind(event.request_type.as_i16())
    .bind(event.duration_ms)
    .execute(pool)
    .await
    .unwrap();
}
