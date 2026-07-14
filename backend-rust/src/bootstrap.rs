use std::{env, fmt};

use anyhow::{Context, Result, bail, ensure};
use rand::{RngCore, rngs::OsRng};
use sqlx::PgPool;

use crate::security::password;

const DEFAULT_ADMIN_EMAIL: &str = "admin@sub2api.local";
const DEFAULT_ADMIN_CONCURRENCY: i32 = 5;
const SIMPLE_MODE_ADMIN_CONCURRENCY: i32 = 30;
const GENERATED_PASSWORD_LENGTH: usize = 24;
const PASSWORD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ADMIN_BOOTSTRAP_LOCK: i64 = 0x5355_4232_4150_4941;

const USERS_EXIST_SQL: &str = "SELECT EXISTS (SELECT 1 FROM users LIMIT 1)";
const ADMIN_INSERT_SQL: &str = r"
INSERT INTO users (email, password_hash, role, balance, concurrency, status)
VALUES ($1, $2, 'admin', 0, $3, 'active')
RETURNING id
";

/// Environment-backed configuration for first-user administrator bootstrap.
///
/// The password is deliberately omitted from `Debug` output.
pub struct AdminBootstrapConfig {
    email: String,
    password: Option<String>,
    concurrency: i32,
}

impl AdminBootstrapConfig {
    /// Builds configuration from optional values. Blank emails use the
    /// `Sub2API` default and blank passwords request secure generation.
    #[must_use]
    pub fn new(email: Option<String>, password: Option<String>) -> Self {
        Self {
            email: email
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_ADMIN_EMAIL.to_owned()),
            password: password.filter(|value| !value.trim().is_empty()),
            concurrency: DEFAULT_ADMIN_CONCURRENCY,
        }
    }

    /// Reads `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and the existing `RUN_MODE`
    /// compatibility switch. No Redis configuration is consulted.
    #[must_use]
    pub fn from_env() -> Self {
        let concurrency = if env::var("RUN_MODE")
            .ok()
            .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("simple"))
        {
            SIMPLE_MODE_ADMIN_CONCURRENCY
        } else {
            DEFAULT_ADMIN_CONCURRENCY
        };
        Self::new(
            env::var("ADMIN_EMAIL").ok(),
            env::var("ADMIN_PASSWORD").ok(),
        )
        .with_concurrency(concurrency)
    }

    /// Overrides administrator concurrency for an embedding application.
    #[must_use]
    pub const fn with_concurrency(mut self, concurrency: i32) -> Self {
        self.concurrency = concurrency;
        self
    }

    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    #[must_use]
    pub fn has_configured_password(&self) -> bool {
        self.password.is_some()
    }

    #[must_use]
    pub const fn concurrency(&self) -> i32 {
        self.concurrency
    }
}

impl Default for AdminBootstrapConfig {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl fmt::Debug for AdminBootstrapConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminBootstrapConfig")
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("concurrency", &self.concurrency)
            .finish()
    }
}

/// Administrator inserted into an otherwise empty users table.
pub struct CreatedAdmin {
    pub id: i64,
    pub email: String,
    generated_password: Option<String>,
}

impl CreatedAdmin {
    /// Returns the generated password only when `ADMIN_PASSWORD` was absent.
    #[must_use]
    pub fn generated_password(&self) -> Option<&str> {
        self.generated_password.as_deref()
    }

    /// Produces the exact one-time line expected by deployment log parsers.
    #[must_use]
    pub fn password_log_line(&self) -> Option<String> {
        self.generated_password
            .as_ref()
            .map(|password| format!("admin password: {password}"))
    }
}

impl fmt::Debug for CreatedAdmin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedAdmin")
            .field("id", &self.id)
            .field("email", &self.email)
            .field(
                "generated_password",
                &self.generated_password.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Result of one idempotent administrator bootstrap attempt.
#[derive(Debug)]
pub enum AdminBootstrapOutcome {
    Created(CreatedAdmin),
    SkippedUsersExist,
}

impl AdminBootstrapOutcome {
    #[must_use]
    pub const fn was_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }

    /// Returns the exact one-time password log line when a password was
    /// generated. Configured passwords are never returned for logging.
    #[must_use]
    pub fn password_log_line(&self) -> Option<String> {
        match self {
            Self::Created(created) => created.password_log_line(),
            Self::SkippedUsersExist => None,
        }
    }
}

/// Creates the initial administrator only while the entire `users` table is
/// empty. A transaction-scoped `PostgreSQL` advisory lock serializes concurrent
/// processes, and the users table is checked again after acquiring that lock.
///
/// # Errors
///
/// Returns an error when `PostgreSQL` cannot be queried, configuration is
/// invalid, secure password generation fails, or bcrypt hashing fails.
pub async fn bootstrap_admin(
    pool: &PgPool,
    config: &AdminBootstrapConfig,
) -> Result<AdminBootstrapOutcome> {
    if users_exist(pool).await? {
        return Ok(AdminBootstrapOutcome::SkippedUsersExist);
    }

    let mut transaction = pool
        .begin()
        .await
        .context("begin administrator bootstrap transaction")?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADMIN_BOOTSTRAP_LOCK)
        .execute(&mut *transaction)
        .await
        .context("acquire administrator bootstrap lock")?;
    if sqlx::query_scalar::<_, bool>(USERS_EXIST_SQL)
        .fetch_one(&mut *transaction)
        .await
        .context("recheck users table during administrator bootstrap")?
    {
        transaction
            .commit()
            .await
            .context("commit skipped administrator bootstrap")?;
        return Ok(AdminBootstrapOutcome::SkippedUsersExist);
    }

    let email = config.email.clone();
    let configured_password = config.password.clone();
    let concurrency = config.concurrency;
    let prepared =
        tokio::task::spawn_blocking(move || prepare_admin(email, configured_password, concurrency))
            .await
            .context("administrator password hashing task failed")??;

    let id = sqlx::query_scalar::<_, i64>(ADMIN_INSERT_SQL)
        .bind(&prepared.email)
        .bind(&prepared.password_hash)
        .bind(prepared.concurrency)
        .fetch_one(&mut *transaction)
        .await
        .context("insert initial administrator")?;
    transaction
        .commit()
        .await
        .context("commit initial administrator")?;

    Ok(AdminBootstrapOutcome::Created(CreatedAdmin {
        id,
        email: prepared.email,
        generated_password: prepared.generated_password,
    }))
}

async fn users_exist(pool: &PgPool) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(USERS_EXIST_SQL)
        .fetch_one(pool)
        .await
        .context("check whether users table is empty")
}

struct PreparedAdmin {
    email: String,
    password_hash: String,
    generated_password: Option<String>,
    concurrency: i32,
}

fn prepare_admin(
    email: String,
    configured_password: Option<String>,
    concurrency: i32,
) -> Result<PreparedAdmin> {
    validate_admin_config(&email, concurrency)?;
    let (plain_password, generated) = match configured_password {
        Some(password) => (password, false),
        None => (generate_admin_password()?, true),
    };
    let password_hash =
        password::hash_password(&plain_password).context("hash initial administrator password")?;
    Ok(PreparedAdmin {
        email,
        password_hash,
        generated_password: generated.then_some(plain_password),
        concurrency,
    })
}

fn validate_admin_config(email: &str, concurrency: i32) -> Result<()> {
    ensure!(!email.is_empty(), "administrator email cannot be empty");
    ensure!(email.len() <= 255, "administrator email exceeds 255 bytes");
    ensure!(
        !email.chars().any(char::is_control),
        "administrator email contains control characters"
    );
    ensure!(
        concurrency > 0,
        "administrator concurrency must be greater than zero"
    );
    Ok(())
}

fn generate_admin_password() -> Result<String> {
    let mut random = [0_u8; GENERATED_PASSWORD_LENGTH];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow::anyhow!("secure random generator failed: {error}"))?;
    let password: String = random
        .into_iter()
        .map(|byte| PASSWORD_ALPHABET[usize::from(byte & 0x3f)] as char)
        .collect();
    if password.is_empty() {
        bail!("secure random generator returned an empty password");
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_existing_setup_contract() {
        let config = AdminBootstrapConfig::default();
        assert_eq!(config.email(), DEFAULT_ADMIN_EMAIL);
        assert!(!config.has_configured_password());
        assert_eq!(config.concurrency(), DEFAULT_ADMIN_CONCURRENCY);
    }

    #[test]
    fn debug_output_redacts_configured_password() {
        let config = AdminBootstrapConfig::new(
            Some("admin@example.com".to_owned()),
            Some("do-not-print".to_owned()),
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("do-not-print"));
    }

    #[test]
    fn generated_password_has_144_bits_of_uniform_alphabet_entropy() {
        let password = generate_admin_password().expect("password generation should succeed");
        assert_eq!(password.len(), GENERATED_PASSWORD_LENGTH);
        assert!(
            password
                .bytes()
                .all(|byte| PASSWORD_ALPHABET.contains(&byte))
        );
    }

    #[test]
    fn configured_password_is_hashed_but_not_returned_for_logging() {
        let prepared = prepare_admin(
            "admin@example.com".to_owned(),
            Some("configured-secret".to_owned()),
            5,
        )
        .expect("administrator should be prepared");
        assert!(
            password::verify_password("configured-secret", &prepared.password_hash)
                .expect("bcrypt hash should verify")
        );
        assert!(prepared.generated_password.is_none());
    }

    #[test]
    fn generated_password_has_exact_log_contract() {
        let created = CreatedAdmin {
            id: 1,
            email: DEFAULT_ADMIN_EMAIL.to_owned(),
            generated_password: Some("generated-secret".to_owned()),
        };
        assert_eq!(
            created.password_log_line().as_deref(),
            Some("admin password: generated-secret")
        );
        assert!(!format!("{created:?}").contains("generated-secret"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    async fn postgres_bootstrap_is_idempotent_and_skips_existing_users() {
        let database_url = env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point at a disposable *_test database");
        let parsed = url::Url::parse(&database_url).expect("database URL should parse");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to modify a database whose name does not end in _test"
        );
        let pool = PgPool::connect(&database_url)
            .await
            .expect("test database should connect");
        sqlx::query("TRUNCATE TABLE users CASCADE")
            .execute(&pool)
            .await
            .expect("test users should reset");

        let config = AdminBootstrapConfig::new(
            Some("rust-admin@example.com".to_owned()),
            Some("integration-secret".to_owned()),
        );
        let first = bootstrap_admin(&pool, &config)
            .await
            .expect("empty database should bootstrap");
        assert!(first.was_created());
        let second = bootstrap_admin(&pool, &config)
            .await
            .expect("second bootstrap should be idempotent");
        assert!(matches!(second, AdminBootstrapOutcome::SkippedUsersExist));
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .expect("users should count");
        assert_eq!(count, 1);

        let row = sqlx::query_as::<_, (String, String, String, String, i32)>(
            "SELECT email, password_hash, role, status, concurrency FROM users LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("administrator should load");
        assert_eq!(row.0, "rust-admin@example.com");
        assert!(
            password::verify_password("integration-secret", &row.1)
                .expect("stored bcrypt hash should verify")
        );
        assert_eq!(row.2, "admin");
        assert_eq!(row.3, "active");
        assert_eq!(row.4, DEFAULT_ADMIN_CONCURRENCY);

        sqlx::query("TRUNCATE TABLE users CASCADE")
            .execute(&pool)
            .await
            .expect("administrator should clean up");
        sqlx::query("INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'user')")
            .bind("existing-user@example.com")
            .bind("not-used-for-login")
            .execute(&pool)
            .await
            .expect("ordinary user should insert");
        let ordinary_user = bootstrap_admin(&pool, &config)
            .await
            .expect("existing ordinary user should skip bootstrap");
        assert!(matches!(
            ordinary_user,
            AdminBootstrapOutcome::SkippedUsersExist
        ));
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .expect("ordinary users should count");
        assert_eq!(count, 1);

        sqlx::query("TRUNCATE TABLE users CASCADE")
            .execute(&pool)
            .await
            .expect("test users should clean up");
        pool.close().await;
    }
}
