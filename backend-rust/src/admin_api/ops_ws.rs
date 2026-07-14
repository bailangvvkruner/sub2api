use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{
    Extension, Router,
    extract::{State, ws::CloseFrame, ws::Message, ws::WebSocket, ws::WebSocketUpgrade},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

use super::{AdminApiState, AdminIdentity};

const PUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_CONNECTIONS: usize = 100;
const REALTIME_DISABLED_CLOSE_CODE: u16 = 4001;
static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn router() -> Router<AdminApiState> {
    Router::new().route("/api/v1/admin/ops/ws/qps", get(qps_websocket))
}

async fn qps_websocket(
    State(state): State<AdminApiState>,
    Extension(_identity): Extension<AdminIdentity>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let Some(permit) = ConnectionPermit::acquire() else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "error": "too many connections" })),
        )
            .into_response();
    };
    let enabled = realtime_enabled(state.service.pool()).await;
    let pool = state.service.pool().clone();
    upgrade
        .protocols(["sub2api-admin"])
        .max_message_size(1_024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            if !enabled {
                let mut socket = socket;
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: REALTIME_DISABLED_CLOSE_CODE,
                        reason: "realtime_disabled".into(),
                    })))
                    .await;
                return;
            }
            serve_qps(socket, pool).await;
        })
}

async fn realtime_enabled(pool: &PgPool) -> bool {
    match sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'ops_realtime_monitoring_enabled'",
    )
    .fetch_optional(pool)
    .await
    {
        Ok(Some(value)) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "off" | "disabled"
        ),
        Ok(None) => true,
        Err(error) => {
            tracing::warn!(error = %error, "read ops realtime monitoring setting");
            true
        }
    }
}

async fn serve_qps(mut socket: WebSocket, pool: PgPool) {
    if send_snapshot(&mut socket, &pool).await.is_err() {
        return;
    }
    let mut interval = tokio::time::interval(PUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if send_snapshot(&mut socket, &pool).await.is_err() {
                    return;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let _ = socket.send(Message::Close(frame)).await;
                        return;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        tracing::debug!(error = %error, "read ops QPS WebSocket");
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

async fn send_snapshot(socket: &mut WebSocket, pool: &PgPool) -> Result<(), ()> {
    let payload = match qps_payload(pool).await {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(error = %error, "load ops QPS WebSocket snapshot");
            let _ = socket
                .send(Message::Text(
                    json!({
                        "type": "error",
                        "error": "failed to load realtime traffic"
                    })
                    .to_string()
                    .into(),
                ))
                .await;
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 1011,
                    reason: "snapshot_failed".into(),
                })))
                .await;
            return Err(());
        }
    };
    socket
        .send(Message::Text(payload.to_string().into()))
        .await
        .map_err(|error| {
            tracing::debug!(error = %error, "write ops QPS WebSocket snapshot");
        })
}

async fn qps_payload(pool: &PgPool) -> Result<Value, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT
    COUNT(*)::bigint AS request_count,
    COALESCE(SUM(input_tokens + output_tokens), 0)::bigint AS token_count
FROM usage_logs
WHERE created_at >= NOW() - INTERVAL '1 minute'
",
    )
    .fetch_one(pool)
    .await?;
    let request_count: i64 = row.try_get("request_count")?;
    let token_count: i64 = row.try_get("token_count")?;
    Ok(build_qps_payload(request_count, token_count))
}

#[allow(clippy::cast_precision_loss)]
fn build_qps_payload(request_count: i64, token_count: i64) -> Value {
    let qps = round_one_decimal(request_count as f64 / 60.0);
    let tps = round_one_decimal(token_count as f64 / 60.0);
    json!({
        "type": "qps_update",
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "data": {
            "qps": qps,
            "tps": tps,
            "request_count": request_count,
        }
    })
}

fn round_one_decimal(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

struct ConnectionPermit;

impl ConnectionPermit {
    fn acquire() -> Option<Self> {
        CONNECTIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CONNECTIONS).then_some(current + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_snapshot_matches_frontend_contract() {
        let payload = build_qps_payload(123, 456);
        assert_eq!(payload["type"], "qps_update");
        assert_eq!(payload["data"]["request_count"], 123);
        assert_eq!(payload["data"]["qps"], 2.1);
        assert_eq!(payload["data"]["tps"], 7.6);
        assert!(payload["timestamp"].as_str().is_some());
    }
}
