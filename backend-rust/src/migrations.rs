use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, PgPool};

use crate::config::{MigrationConfig, MigrationMode};

static MIGRATIONS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/migrations");

const MIGRATIONS_ADVISORY_LOCK_ID: i64 = 694_208_311_321_144_027;
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(500);
const NON_TRANSACTIONAL_SUFFIX: &str = "_notx.sql";
const OPS_SYSTEM_LOGS_API_KEY_INDEX: &str = "idx_ops_system_logs_api_key_id_created_at";

const SCHEMA_MIGRATIONS_DDL: &str = r"
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT PRIMARY KEY,
    checksum   TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
";

const ATLAS_REVISIONS_DDL: &str = r"
CREATE TABLE IF NOT EXISTS atlas_schema_revisions (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    type INTEGER NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    execution_time BIGINT NOT NULL DEFAULT 0,
    error TEXT NULL,
    error_stmt TEXT NULL,
    hash TEXT NOT NULL DEFAULT '',
    partial_hashes TEXT[] NULL,
    operator_version TEXT NULL
)
";

#[derive(Debug, Default, Eq, PartialEq)]
pub struct MigrationReport {
    pub applied: usize,
    pub unchanged: usize,
}

struct EmbeddedMigration {
    name: String,
    content: &'static str,
}

/// Applies or validates the embedded `PostgreSQL` migrations.
///
/// # Errors
///
/// Returns an error when `PostgreSQL` is unavailable, migration locking fails,
/// a migration checksum changed, or any migration statement fails.
pub async fn run(pool: &PgPool, config: &MigrationConfig) -> Result<MigrationReport> {
    match config.mode {
        MigrationMode::Off => Ok(MigrationReport::default()),
        MigrationMode::Apply | MigrationMode::Validate => run_with_timeout(pool, config).await,
    }
}

async fn run_with_timeout(pool: &PgPool, config: &MigrationConfig) -> Result<MigrationReport> {
    let operation = async {
        // PostgreSQL advisory locks are session scoped. Keep every migration
        // query on this connection, and close it instead of returning a
        // potentially locked/canceled session to the pool if this future drops.
        let mut connection = pool
            .acquire()
            .await
            .context("acquire PostgreSQL connection for migrations")?;
        connection.close_on_drop();
        run_on_locked_connection(&mut connection, config.mode).await
    };
    match tokio::time::timeout(config.timeout, operation).await {
        Ok(result) => result,
        Err(_) => bail!(
            "PostgreSQL migration operation timed out after {:?}",
            config.timeout
        ),
    }
}

async fn run_on_locked_connection(
    connection: &mut PgConnection,
    mode: MigrationMode,
) -> Result<MigrationReport> {
    acquire_advisory_lock(connection).await?;
    let result = match mode {
        MigrationMode::Apply => apply_locked(connection).await,
        MigrationMode::Validate => validate_locked(connection).await,
        MigrationMode::Off => unreachable!("off mode is handled before connection acquisition"),
    };
    let unlock_result = release_advisory_lock(connection).await;
    match (result, unlock_result) {
        (Ok(report), Ok(())) => {
            tracing::info!(
                applied = report.applied,
                unchanged = report.unchanged,
                "PostgreSQL migrations are current"
            );
            Ok(report)
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(unlock_error)) => Err(unlock_error),
        (Err(error), Err(unlock_error)) => Err(error.context(format!(
            "also failed to release migration advisory lock: {unlock_error:#}"
        ))),
    }
}

async fn apply_locked(connection: &mut PgConnection) -> Result<MigrationReport> {
    sqlx::query(SCHEMA_MIGRATIONS_DDL)
        .execute(&mut *connection)
        .await
        .context("create schema_migrations")?;
    let mut report = MigrationReport::default();
    for migration in embedded_migrations()? {
        let content = migration.content.trim();
        if content.is_empty() {
            continue;
        }
        let checksum = checksum(content);
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT checksum FROM schema_migrations WHERE filename = $1",
        )
        .bind(&migration.name)
        .fetch_optional(&mut *connection)
        .await
        .with_context(|| format!("check migration {}", migration.name))?;

        if let Some(existing) = existing {
            verify_checksum(&migration.name, &existing, &checksum)?;
            report.unchanged += 1;
            continue;
        }

        let non_transactional = validate_execution_mode(&migration.name, content)
            .with_context(|| format!("validate migration {}", migration.name))?;
        if non_transactional {
            prepare_non_transactional(connection, &migration.name).await?;
            if !apply_special_non_transactional(connection, &migration.name).await? {
                for (index, statement) in split_sql_statements(content).into_iter().enumerate() {
                    if strip_line_comments(statement).is_empty() {
                        continue;
                    }
                    sqlx::query(statement)
                        .execute(&mut *connection)
                        .await
                        .with_context(|| {
                            format!(
                                "apply migration {} non-transactional statement {}",
                                migration.name,
                                index + 1
                            )
                        })?;
                }
            }
            record_migration(connection, &migration.name, &checksum).await?;
        } else {
            let mut transaction = connection
                .begin()
                .await
                .with_context(|| format!("begin migration {}", migration.name))?;
            sqlx::raw_sql(content)
                .execute(&mut *transaction)
                .await
                .with_context(|| format!("apply migration {}", migration.name))?;
            sqlx::query("INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)")
                .bind(&migration.name)
                .bind(&checksum)
                .execute(&mut *transaction)
                .await
                .with_context(|| format!("record migration {}", migration.name))?;
            transaction
                .commit()
                .await
                .with_context(|| format!("commit migration {}", migration.name))?;
        }
        report.applied += 1;
    }
    // Do not advertise the latest Atlas baseline until every legacy
    // migration has succeeded. A partial fresh schema must not look current.
    ensure_atlas_baseline(connection).await?;
    Ok(report)
}

async fn validate_locked(connection: &mut PgConnection) -> Result<MigrationReport> {
    let table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.schema_migrations')::text")
            .fetch_one(&mut *connection)
            .await
            .context("check schema_migrations")?;
    if table.is_none() {
        bail!("schema_migrations does not exist; run with MIGRATIONS_MODE=apply");
    }

    let mut report = MigrationReport::default();
    let mut pending = Vec::new();
    for migration in embedded_migrations()? {
        let content = migration.content.trim();
        if content.is_empty() {
            continue;
        }
        let actual = checksum(content);
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT checksum FROM schema_migrations WHERE filename = $1",
        )
        .bind(&migration.name)
        .fetch_optional(&mut *connection)
        .await
        .with_context(|| format!("check migration {}", migration.name))?;
        match existing {
            Some(existing) => {
                verify_checksum(&migration.name, &existing, &actual)?;
                report.unchanged += 1;
            }
            None => pending.push(migration.name),
        }
    }
    if !pending.is_empty() {
        let sample = pending
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "{} PostgreSQL migrations are pending (first: {sample}); run with MIGRATIONS_MODE=apply",
            pending.len()
        );
    }
    Ok(report)
}

async fn record_migration(
    connection: &mut PgConnection,
    name: &str,
    migration_checksum: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)")
        .bind(name)
        .bind(migration_checksum)
        .execute(connection)
        .await
        .with_context(|| format!("record migration {name}"))?;
    Ok(())
}

async fn ensure_atlas_baseline(connection: &mut PgConnection) -> Result<()> {
    sqlx::query(ATLAS_REVISIONS_DDL)
        .execute(&mut *connection)
        .await
        .context("create atlas_schema_revisions")?;
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM atlas_schema_revisions")
        .fetch_one(&mut *connection)
        .await
        .context("count atlas_schema_revisions")?;
    if count > 0 {
        return Ok(());
    }

    let migrations = embedded_migrations()?;
    let Some(latest) = migrations.last() else {
        return Ok(());
    };
    let version = latest.name.trim_end_matches(".sql");
    let hash = checksum(latest.content.trim());
    sqlx::query(
        r"INSERT INTO atlas_schema_revisions
           (version, description, type, applied, total, executed_at, execution_time, hash)
           VALUES ($1, $2, 1, 0, 0, NOW(), 0, $3)",
    )
    .bind(version)
    .bind(version)
    .bind(hash)
    .execute(connection)
    .await
    .context("insert Atlas migration baseline")?;
    Ok(())
}

async fn acquire_advisory_lock(connection: &mut PgConnection) -> Result<()> {
    loop {
        let locked = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
            .bind(MIGRATIONS_ADVISORY_LOCK_ID)
            .fetch_one(&mut *connection)
            .await
            .context("acquire migration advisory lock")?;
        if locked {
            return Ok(());
        }
        tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
    }
}

async fn release_advisory_lock(connection: &mut PgConnection) -> Result<()> {
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATIONS_ADVISORY_LOCK_ID)
        .fetch_one(connection)
        .await
        .context("release migration advisory lock")?;
    if !unlocked {
        bail!("PostgreSQL reported that the migration advisory lock was not held");
    }
    Ok(())
}

fn embedded_migrations() -> Result<Vec<EmbeddedMigration>> {
    let mut migrations = MIGRATIONS
        .files()
        .filter(|file| {
            file.path()
                .extension()
                .is_some_and(|extension| extension == "sql")
        })
        .map(|file| {
            let name = file
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    anyhow!(
                        "migration path is not valid UTF-8: {}",
                        file.path().display()
                    )
                })?;
            let content = file
                .contents_utf8()
                .ok_or_else(|| anyhow!("migration {name} is not valid UTF-8"))?;
            Ok(EmbeddedMigration {
                name: name.to_owned(),
                content,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    migrations.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(migrations)
}

fn checksum(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))
}

fn verify_checksum(name: &str, database: &str, file: &str) -> Result<()> {
    if database == file || checksum_is_compatible(name, database, file) {
        return Ok(());
    }
    bail!(
        "migration {name} checksum mismatch (db={database}, file={file}); applied migrations are immutable"
    )
}

fn checksum_is_compatible(name: &str, database: &str, file: &str) -> bool {
    let known: &[&str] = match name {
        "054_drop_legacy_cache_columns.sql" => &[
            "82de761156e03876653e7a6a4eee883cd927847036f779b0b9f34c42a8af7a7d",
            "182c193f3359946cf094090cd9e57d5c3fd9abaffbc1e8fc378646b8a6fa12b4",
        ],
        "061_add_usage_log_request_type.sql" => &[
            "66207e7aa5dd0429c2e2c0fabdaf79783ff157fa0af2e81adff2ee03790ec65c",
            "08a248652cbab7cfde147fc6ef8cda464f2477674e20b718312faa252e0481c0",
            "222b4a09c797c22e5922b6b172327c824f5463aaa8760e4f621bc5c22e2be0f3",
        ],
        "109_auth_identity_compat_backfill.sql" => &[
            "0580b4602d85435edf9aca1633db580bb3932f26517f75134106f80275ec2ace",
            "551e498aa5616d2d91096e9d72cf9fb36e418ee22eacc557f8811cadbc9e20ee",
        ],
        "110_pending_auth_and_provider_default_grants.sql" => &[
            "32cf87ee787b1bb36b5c691367c96eee37518fa3eed6f3322cf68795e3745279",
            "e3d1f433be2b564cfbdc549adf98fce13c5c7b363ebc20fd05b765d0563b0925",
        ],
        "112_add_payment_order_provider_key_snapshot.sql" => &[
            "b75f8f56d39455682787696a3d92ad25b055444ca328fb7fca9a460a15d68d99",
            "ffd3e8a2c9295fa9cbefefd629a78268877e5b51bc970a82d9b3f46ec4ebd15e",
        ],
        "115_auth_identity_legacy_external_backfill.sql" => &[
            "022aadd97bb53e755f0cf7a3a957e0cb1a1353b0c39ec4de3234acd2871fd04f",
            "4cf39e508be9fd1a5aa41610cbbebeb80385c9adda45bf78a706de9db4f1385f",
        ],
        "116_auth_identity_legacy_external_safety_reports.sql" => &[
            "07edb09fa8d04ffb172b0621e3c22f4d1757d20a24ae267b3b36b087ab72d488",
            "f7757bd929ac67ffb08ce69fa4cf20fad39dbff9d5a5085fb2adabb7607e5877",
        ],
        "118_wechat_dual_mode_and_auth_source_defaults.sql" => &[
            "b54194d7a3e4fbf710e0a3590d22a2fe7966804c487052a356e0b55f53ef96b0",
            "e0cdf835d6c688d64100f483d31bc02ac9ebad414bf1837af239a84bf75b8227",
            "a38243ca0a72c3a01c0a92b7986423054d6133c0399441f853b99802852720fb",
        ],
        "119_enforce_payment_orders_out_trade_no_unique.sql" => &[
            "0bbe809ae48a9d811dabda1ba1c74955bd71c4a9cc610f9128816818dfa6c11e",
            "ebd2c67cce0116393fb4f1b5d5116a67c6aceb73820dfb5133d1ff6f36d72d34",
        ],
        "120_enforce_payment_orders_out_trade_no_unique_notx.sql" => &[
            "34aadc0db59a4e390f92a12b73bd74642d9724f33124f73638ae00089ea5e074",
            "e77921f79d539bc24575cb9c16cbe566d2b23ce816190343d0a7568f6a3fcf61",
            "707431450603e70a43ce9fbd61e0c12fa67da4875158ccefabacea069587ab22",
            "04b082b5a239c525154fe9185d324ee2b05ff90da9297e10dba19f9be79aa59a",
        ],
        "123_fix_legacy_auth_source_grant_on_signup_defaults.sql" => &[
            "2ce43c2cd89e9f9e1febd34a407ed9e84d177386c5544b6f02c1f58a21129f57",
            "6cd33422f215dcd1f486ab6f35c0ea5805d9ca69bb25906d94bc649156657145",
        ],
        "159_batch_image_foundation.sql" => &[
            "d902b70982025ec519749faf058aab7631e82c3f48167b9a4ae4db718eb72cce",
            "82da85b5d98e67a0507647b873a40373e84538e4adafdeed6767c0ac8b6570b2",
        ],
        "161_batch_image_pricing_snapshot.sql" => &[
            "4012af3e43636cb6af22e0176d59d1fcc70615c0f310194329461ae462c4fbd6",
            "96d915c9b7a6941ae99039e0ff3f1a61481eb9bddd933d11c6fadb2274554e87",
        ],
        _ => return false,
    };
    known.contains(&database) && known.contains(&file)
}

fn validate_execution_mode(name: &str, content: &str) -> Result<bool> {
    let non_transactional = name
        .trim()
        .to_ascii_lowercase()
        .ends_with(NON_TRANSACTIONAL_SUFFIX);
    let upper = content.to_ascii_uppercase();
    if !non_transactional {
        if upper.contains("CONCURRENTLY") {
            bail!("CONCURRENTLY statements must be placed in *_notx.sql migrations");
        }
        return Ok(false);
    }
    if ["BEGIN", "COMMIT", "ROLLBACK"]
        .iter()
        .any(|keyword| upper.contains(keyword))
    {
        bail!("*_notx.sql must not contain transaction control statements");
    }
    for statement in split_sql_statements(content) {
        let normalized = strip_line_comments(statement).to_ascii_uppercase();
        if normalized.is_empty() {
            continue;
        }
        if !normalized.contains("CONCURRENTLY") {
            bail!("*_notx.sql must not mix non-CONCURRENTLY SQL statements");
        }
        let create = normalized.contains("CREATE") && normalized.contains("INDEX");
        let drop = normalized.contains("DROP") && normalized.contains("INDEX");
        if !create && !drop {
            bail!("*_notx.sql only supports CREATE/DROP INDEX CONCURRENTLY");
        }
        if create && !normalized.contains("IF NOT EXISTS") {
            bail!("CREATE INDEX CONCURRENTLY must include IF NOT EXISTS");
        }
        if drop && !normalized.contains("IF EXISTS") {
            bail!("DROP INDEX CONCURRENTLY must include IF EXISTS");
        }
    }
    Ok(true)
}

fn split_sql_statements(content: &str) -> Vec<&str> {
    content
        .split(';')
        .filter(|statement| !statement.trim().is_empty())
        .map(str::trim)
        .collect()
}

fn strip_line_comments(content: &str) -> String {
    content
        .lines()
        .map(|line| line.split_once("--").map_or(line, |(sql, _)| sql))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn concurrent_index_names(name: &str) -> &'static [&'static str] {
    match name {
        "062_add_scheduler_and_usage_composite_indexes_notx.sql" => &[
            "idx_accounts_schedulable_hot",
            "idx_accounts_active_schedulable",
            "idx_user_subscriptions_user_status_expires_active",
            "idx_usage_logs_group_created_at_not_null",
        ],
        "072_add_usage_billing_dedup_created_at_brin_notx.sql" => {
            &["idx_usage_billing_dedup_created_at_brin"]
        }
        "076_add_usage_log_upstream_model_index_notx.sql" => {
            &["idx_usage_logs_created_model_upstream_model"]
        }
        "078_add_usage_log_requested_model_index_notx.sql" => {
            &["idx_usage_logs_created_requested_model_upstream_model"]
        }
        "120_enforce_payment_orders_out_trade_no_unique_notx.sql" => {
            &["paymentorder_out_trade_no_unique"]
        }
        "148_add_ops_error_logs_user_time_index_notx.sql" => &["idx_ops_error_logs_user_time"],
        "150_account_group_scheduler_indexes_notx.sql" => &[
            "idx_account_groups_group_priority_account",
            "idx_account_groups_account_priority_group",
        ],
        "151_account_autopause_expiry_index_notx.sql" => &["idx_accounts_autopause_expiry_due"],
        "153_scheduler_outbox_pending_dedup_key_index_notx.sql" => {
            &["idx_scheduler_outbox_pending_dedup_key"]
        }
        "154a_account_spark_shadow_indexes_notx.sql" => &[
            "idx_accounts_parent_account_id",
            "uq_accounts_spark_shadow_per_parent",
        ],
        // Migration 155 uses a partition-aware handler that validates and
        // repairs each leaf index before attaching it to the parent.
        _ => &[],
    }
}

async fn prepare_non_transactional(connection: &mut PgConnection, name: &str) -> Result<()> {
    for index in concurrent_index_names(name) {
        drop_invalid_index(connection, "public", index).await?;
    }

    if name == "120_enforce_payment_orders_out_trade_no_unique_notx.sql" {
        let duplicates = sqlx::query_as::<_, (String, i64)>(
            r"SELECT out_trade_no, COUNT(*)
                   FROM payment_orders
                   WHERE out_trade_no <> ''
                   GROUP BY out_trade_no
                   HAVING COUNT(*) > 1
                   ORDER BY COUNT(*) DESC, out_trade_no
                   LIMIT 5",
        )
        .fetch_all(&mut *connection)
        .await
        .context("precheck duplicate payment order out_trade_no values")?;
        if !duplicates.is_empty() {
            let detail = duplicates
                .into_iter()
                .map(|(value, count)| format!("{value} (count={count})"))
                .collect::<Vec<_>>()
                .join(", ");
            bail!("duplicate out_trade_no values block migration 120: {detail}");
        }
    }
    Ok(())
}

async fn apply_special_non_transactional(
    connection: &mut PgConnection,
    name: &str,
) -> Result<bool> {
    if name != "155_add_ops_system_logs_api_key_id_index_notx.sql" {
        return Ok(false);
    }
    let partitioned = sqlx::query_scalar::<_, bool>(
        r"SELECT EXISTS (
               SELECT 1 FROM pg_partitioned_table pt
               JOIN pg_class cls ON cls.oid = pt.partrelid
               JOIN pg_namespace ns ON ns.oid = cls.relnamespace
               WHERE ns.nspname = 'public' AND cls.relname = 'ops_system_logs'
           )",
    )
    .fetch_one(&mut *connection)
    .await
    .context("check ops_system_logs partitioning")?;
    if !partitioned {
        // On the normal non-partitioned schema this migration follows the
        // generic path, so repair a failed prior CONCURRENTLY attempt first.
        drop_invalid_index(connection, "public", OPS_SYSTEM_LOGS_API_KEY_INDEX).await?;
        return Ok(false);
    }

    sqlx::query(&format!(
        "CREATE INDEX IF NOT EXISTS {} ON ONLY {} (api_key_id, created_at DESC)",
        quote_identifier(OPS_SYSTEM_LOGS_API_KEY_INDEX),
        qualified_identifier("public", "ops_system_logs")
    ))
    .execute(&mut *connection)
    .await
    .context("create ops_system_logs partitioned parent index")?;

    let partitions = sqlx::query_as::<_, (String, String)>(
        r"WITH RECURSIVE partition_tree AS (
               SELECT child.oid
               FROM pg_inherits inh
               JOIN pg_class child ON child.oid = inh.inhrelid
               WHERE inh.inhparent = to_regclass('public.ops_system_logs')
               UNION ALL
               SELECT child.oid
               FROM pg_inherits inh
               JOIN pg_class child ON child.oid = inh.inhrelid
               JOIN partition_tree parent ON parent.oid = inh.inhparent
           )
           SELECT ns.nspname, cls.relname
           FROM partition_tree pt
           JOIN pg_class cls ON cls.oid = pt.oid
           JOIN pg_namespace ns ON ns.oid = cls.relnamespace
           WHERE NOT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = cls.oid)
           ORDER BY ns.nspname, cls.relname",
    )
    .fetch_all(&mut *connection)
    .await
    .context("list ops_system_logs leaf partitions")?;

    for (schema, partition) in partitions {
        let child_index = partition_index_name(&partition);
        drop_invalid_index(connection, &schema, &child_index).await?;
        sqlx::query(&format!(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON {} (api_key_id, created_at DESC)",
            quote_identifier(&child_index),
            qualified_identifier(&schema, &partition)
        ))
        .execute(&mut *connection)
        .await
        .with_context(|| format!("create partition index {child_index}"))?;

        let attached = sqlx::query_scalar::<_, bool>(
            r"SELECT EXISTS (
                   SELECT 1 FROM pg_inherits inh
                   JOIN pg_class p ON p.oid = inh.inhparent
                   JOIN pg_namespace pn ON pn.oid = p.relnamespace
                   JOIN pg_class c ON c.oid = inh.inhrelid
                   JOIN pg_namespace cn ON cn.oid = c.relnamespace
                   WHERE pn.nspname = 'public' AND p.relname = $1
                     AND cn.nspname = $2 AND c.relname = $3
               )",
        )
        .bind(OPS_SYSTEM_LOGS_API_KEY_INDEX)
        .bind(&schema)
        .bind(&child_index)
        .fetch_one(&mut *connection)
        .await
        .with_context(|| format!("check partition index attachment {child_index}"))?;
        if !attached {
            sqlx::query(&format!(
                "ALTER INDEX {} ATTACH PARTITION {}",
                qualified_identifier("public", OPS_SYSTEM_LOGS_API_KEY_INDEX),
                qualified_identifier(&schema, &child_index)
            ))
            .execute(&mut *connection)
            .await
            .with_context(|| format!("attach partition index {child_index}"))?;
        }
    }
    Ok(true)
}

async fn drop_invalid_index(
    connection: &mut PgConnection,
    schema: &str,
    index: &str,
) -> Result<()> {
    let invalid = sqlx::query_scalar::<_, bool>(
        r"SELECT EXISTS (
               SELECT 1 FROM pg_class idx
               JOIN pg_namespace ns ON ns.oid = idx.relnamespace
               JOIN pg_index i ON i.indexrelid = idx.oid
               WHERE ns.nspname = $1 AND idx.relname = $2 AND NOT i.indisvalid
           )",
    )
    .bind(schema)
    .bind(index)
    .fetch_one(&mut *connection)
    .await
    .with_context(|| format!("check invalid index {schema}.{index}"))?;
    if invalid {
        sqlx::query(&format!(
            "DROP INDEX CONCURRENTLY IF EXISTS {}",
            qualified_identifier(schema, index)
        ))
        .execute(connection)
        .await
        .with_context(|| format!("drop invalid index {schema}.{index}"))?;
    }
    Ok(())
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn qualified_identifier(schema: &str, identifier: &str) -> String {
    format!(
        "{}.{}",
        quote_identifier(schema),
        quote_identifier(identifier)
    )
}

fn partition_index_name(partition: &str) -> String {
    const PREFIX: &str = "idx_ops_system_logs_api_key_id_created_at";
    const MAX_IDENTIFIER_BYTES: usize = 63;
    let suffix = partition
        .strip_prefix("ops_system_logs")
        .filter(|suffix| !suffix.is_empty())
        .map_or_else(|| format!("_{partition}"), str::to_owned);
    let full = format!("{PREFIX}{suffix}");
    if full.len() <= MAX_IDENTIFIER_BYTES {
        return full;
    }
    let hash_suffix = format!("_{}", &checksum(&full)[..8]);
    let mut end = MAX_IDENTIFIER_BYTES - hash_suffix.len();
    while !full.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{hash_suffix}", &full[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_are_sorted_and_complete() {
        let migrations = embedded_migrations().expect("embedded migrations should load");
        assert!(migrations.len() >= 200);
        assert_eq!(
            migrations.first().map(|item| item.name.as_str()),
            Some("001_init.sql")
        );
        assert!(
            migrations
                .windows(2)
                .all(|pair| pair[0].name < pair[1].name)
        );
    }

    #[test]
    fn every_embedded_migration_has_a_valid_execution_mode() {
        for migration in embedded_migrations().expect("embedded migrations should load") {
            validate_execution_mode(&migration.name, migration.content.trim())
                .unwrap_or_else(|error| panic!("{}: {error:#}", migration.name));
        }
    }

    #[test]
    fn every_generic_concurrent_index_has_retry_cleanup() {
        for migration in embedded_migrations().expect("embedded migrations should load") {
            if !migration.name.ends_with(NON_TRANSACTIONAL_SUFFIX)
                || migration.name == "155_add_ops_system_logs_api_key_id_index_notx.sql"
            {
                continue;
            }
            let create_count = migration
                .content
                .to_ascii_uppercase()
                .matches("INDEX CONCURRENTLY IF NOT EXISTS")
                .count();
            let names = concurrent_index_names(&migration.name);
            assert_eq!(
                names.len(),
                create_count,
                "{} must list every concurrently-created index",
                migration.name
            );
            for name in names {
                assert!(
                    migration.content.contains(name),
                    "{} does not contain mapped index {name}",
                    migration.name
                );
            }
        }
    }

    #[test]
    fn checksum_matches_the_go_runner_contract() {
        assert_eq!(
            checksum("SELECT 1;"),
            "17db4fd369edb9244b9f91d9aeed145c3d04ad8ba6e95d06247f07a63527d11a"
        );
    }

    #[test]
    fn long_partition_index_names_stay_within_postgres_limit() {
        let name = partition_index_name(&format!("ops_system_logs_{}", "x".repeat(100)));
        assert!(name.len() <= 63);
        assert!(name.starts_with("idx_ops_system_logs_api_key_id_created_at"));
    }
}
