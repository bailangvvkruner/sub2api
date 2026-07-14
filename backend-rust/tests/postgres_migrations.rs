use std::{env, time::Duration};

use sqlx::postgres::PgPoolOptions;
use sub2api_rust::{
    config::{MigrationConfig, MigrationMode},
    migrations,
};

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable *_test database"]
async fn applies_all_embedded_migrations_idempotently() {
    let database_url = env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must point at a disposable *_test database");
    let parsed = url::Url::parse(&database_url).expect("TEST_DATABASE_URL must be a valid URL");
    let database_name = parsed.path().trim_matches('/');
    assert!(
        database_name.ends_with("_test"),
        "refusing to reset a database whose name does not end in _test"
    );

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect to the PostgreSQL integration database");
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION CURRENT_USER;")
        .execute(&pool)
        .await
        .expect("reset the dedicated PostgreSQL integration schema");
    let apply = MigrationConfig {
        mode: MigrationMode::Apply,
        timeout: Duration::from_mins(1),
    };

    let first = migrations::run(&pool, &apply)
        .await
        .expect("apply migrations to an empty PostgreSQL database");
    assert!(first.applied >= 200, "expected the full migration history");

    let second = migrations::run(&pool, &apply)
        .await
        .expect("reapplying migrations should be idempotent");
    assert_eq!(second.applied, 0);
    assert_eq!(second.unchanged, first.applied + first.unchanged);

    let validate = MigrationConfig {
        mode: MigrationMode::Validate,
        timeout: Duration::from_mins(1),
    };
    let validated = migrations::run(&pool, &validate)
        .await
        .expect("validate the fully migrated database");
    assert_eq!(validated.unchanged, second.unchanged);

    let recorded = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("count applied migrations");
    let recorded = usize::try_from(recorded).expect("migration count must be non-negative");
    assert_eq!(recorded, second.unchanged);

    let mut blocker = pool
        .acquire()
        .await
        .expect("acquire a connection that blocks the migration lock");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(694_208_311_321_144_027_i64)
        .execute(&mut *blocker)
        .await
        .expect("hold the migration advisory lock");
    let blocked_validate = MigrationConfig {
        mode: MigrationMode::Validate,
        timeout: Duration::from_millis(100),
    };
    let timeout_error = migrations::run(&pool, &blocked_validate)
        .await
        .expect_err("validation must honor the complete migration timeout");
    assert!(timeout_error.to_string().contains("timed out"));
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(694_208_311_321_144_027_i64)
        .fetch_one(&mut *blocker)
        .await
        .expect("release the blocking migration advisory lock");
    assert!(unlocked);
    drop(blocker);

    pool.close().await;
}
