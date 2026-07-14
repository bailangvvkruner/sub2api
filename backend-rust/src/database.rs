use std::time::Duration;

use anyhow::{Context, Result, bail};
use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::config::DatabaseConfig;

/// Opens and verifies the `PostgreSQL` connection pool.
///
/// # Errors
///
/// Returns an error when the pool cannot connect or the readiness query fails.
pub async fn connect(config: &DatabaseConfig) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .min_connections(config.min_connections)
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .max_lifetime(Some(config.max_lifetime))
        .idle_timeout(Some(config.idle_timeout))
        .connect(&config.url)
        .await
        .context("connect to PostgreSQL")?;

    ping(&pool).await.context("ping PostgreSQL")?;
    Ok(pool)
}

/// Executes a minimal `PostgreSQL` readiness query.
///
/// # Errors
///
/// Returns an error when a connection cannot be acquired or the query fails.
pub async fn ping(pool: &PgPool) -> Result<()> {
    const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
    let mut connection = pool
        .acquire()
        .await
        .context("acquire PostgreSQL readiness connection")?;
    let query = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&mut *connection);
    let value = if let Ok(result) = tokio::time::timeout(QUERY_TIMEOUT, query).await {
        result.context("execute PostgreSQL readiness query")?
    } else {
        // A canceled query may leave unread protocol frames on the socket.
        connection.close_on_drop();
        bail!("PostgreSQL readiness query timed out after {QUERY_TIMEOUT:?}");
    };
    anyhow::ensure!(value == 1, "PostgreSQL readiness query returned {value}");
    Ok(())
}
