use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    sync::Arc,
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::Response,
};
use futures_util::{StreamExt, stream};
use sqlx::postgres::PgPoolOptions;
use sub2api_rust::{
    admin_api::{AdminApi, AdminService, Hs256AdminTokenVerifier, PasswordHasher},
    control_api::{ControlApiConfig, ControlApiState, router as control_router},
    gateway::{GatewayRuntime, GatewayRuntimeConfig},
    http::{AppState, router_with_control},
    payment_api::{PaymentApiState, router as payment_router},
    route_contract,
    user_api::router as user_router,
    user_usage::UserUsageApi,
};
use tower::ServiceExt;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MATCHED_PATH_HEADER: HeaderName = HeaderName::from_static("x-route-audit-matched-path");

struct AuditPasswordHasher;

impl PasswordHasher for AuditPasswordHasher {
    fn hash_password(&self, _password: &str) -> Result<String, String> {
        Ok("audit-only-hash".to_owned())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Coverage {
    Mounted,
    MountedTimeout,
    IntentionalAbsence,
    Missing,
}

impl Coverage {
    const fn label(self) -> &'static str {
        match self {
            Self::Mounted => "mounted",
            Self::MountedTimeout => "mounted_timeout",
            Self::IntentionalAbsence => "intentional_absence",
            Self::Missing => "missing",
        }
    }
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn Error>> {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(5))
        .connect_lazy("postgresql://sub2api@127.0.0.1/sub2api")?;
    let control = ControlApiState::new(pool.clone(), ControlApiConfig::new([7_u8; 32]))?;
    let (gateway, gateway_worker) =
        GatewayRuntime::spawn(pool.clone(), GatewayRuntimeConfig::default())?;
    let admin = AdminApi::new(
        AdminService::new(pool.clone(), Arc::new(AuditPasswordHasher)),
        Arc::new(Hs256AdminTokenVerifier::new([9_u8; 32])?),
    )
    .router();
    let control_routes = control_router(control.clone())
        .merge(user_router(control.clone()))
        .merge(UserUsageApi::new(control.clone()).router())
        .merge(payment_router(PaymentApiState::new(
            pool.clone(),
            control,
            vec![11_u8; 32],
        )))
        .merge(admin);
    let app = router_with_control(
        AppState::new(pool).with_gateway(gateway),
        Some(control_routes),
    )
    .layer(middleware::from_fn(record_matched_path));

    let probes = route_contract::routes().enumerate().map(|(index, route)| {
        let app = app.clone();
        async move {
            let method = Method::from_bytes(route.method.as_bytes())?;
            let path = route.representative_path();
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                app.oneshot(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .body(Body::empty())?,
                ),
            )
            .await;
            let (status, body, matched_path, timed_out) = match response {
                Ok(Ok(response)) => {
                    let status = response.status();
                    let matched_path = response
                        .headers()
                        .get(&MATCHED_PATH_HEADER)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES).await?;
                    (Some(status), body, matched_path, false)
                }
                Ok(Err(error)) => match error {},
                Err(_) => (None, axum::body::Bytes::new(), None, true),
            };
            Ok::<_, Box<dyn Error>>((index, route, path, status, body, matched_path, timed_out))
        }
    });
    let mut probe_results = stream::iter(probes)
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    probe_results.sort_by_key(|(index, ..)| *index);

    let mut rows = Vec::new();
    let mut category_counts = BTreeMap::<(&str, Coverage), usize>::new();
    let mut unique_keys = HashSet::new();
    let mut missing_keys = HashSet::new();
    for (_, route, path, status, body, matched_path, timed_out) in probe_results {
        let coverage = if is_intentional_absence(route.method, route.path) {
            Coverage::IntentionalAbsence
        } else if timed_out {
            Coverage::MountedTimeout
        } else if matched_path.as_deref().is_some_and(|matched| {
            canonical_route_shape(matched) != canonical_route_shape(route.path)
        }) || is_missing_response(status.expect("completed probe has status"), &body)
        {
            Coverage::Missing
        } else {
            Coverage::Mounted
        };
        *category_counts
            .entry((route.category, coverage))
            .or_default() += 1;
        unique_keys.insert((route.method, route.path));
        if coverage == Coverage::Missing {
            missing_keys.insert((route.method, route.path));
        }
        rows.push((route, path, matched_path, status, coverage));
    }

    let mounted = rows
        .iter()
        .filter(|(_, _, _, _, coverage)| *coverage == Coverage::Mounted)
        .count();
    let intentional = rows
        .iter()
        .filter(|(_, _, _, _, coverage)| *coverage == Coverage::IntentionalAbsence)
        .count();
    let mounted_timeout = rows
        .iter()
        .filter(|(_, _, _, _, coverage)| *coverage == Coverage::MountedTimeout)
        .count();
    let missing = rows.len() - mounted - mounted_timeout - intentional;
    println!(
        "SUMMARY\trecords={}\tunique={}\tmounted={}\tmounted_timeout={}\tintentional_absence={}\tmissing={}\tmissing_unique={}",
        rows.len(),
        unique_keys.len(),
        mounted,
        mounted_timeout,
        intentional,
        missing,
        missing_keys.len()
    );
    println!("CATEGORY\tcategory\tmounted\tmounted_timeout\tintentional_absence\tmissing\ttotal");
    let categories = category_counts
        .keys()
        .map(|(category, _)| *category)
        .collect::<std::collections::BTreeSet<_>>();
    for category in categories {
        let mounted = category_counts
            .get(&(category, Coverage::Mounted))
            .copied()
            .unwrap_or_default();
        let intentional = category_counts
            .get(&(category, Coverage::IntentionalAbsence))
            .copied()
            .unwrap_or_default();
        let mounted_timeout = category_counts
            .get(&(category, Coverage::MountedTimeout))
            .copied()
            .unwrap_or_default();
        let missing = category_counts
            .get(&(category, Coverage::Missing))
            .copied()
            .unwrap_or_default();
        println!(
            "CATEGORY\t{category}\t{mounted}\t{mounted_timeout}\t{intentional}\t{missing}\t{}",
            mounted + mounted_timeout + intentional + missing
        );
    }
    println!(
        "ROUTE\tcoverage\tmethod\tpath\trepresentative\tmatched_path\tstatus\tcategory\thandler"
    );
    for (route, representative, matched_path, status, coverage) in rows {
        let status = status.map_or(0, |status| status.as_u16());
        println!(
            "ROUTE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            coverage.label(),
            route.method,
            route.path,
            representative,
            matched_path.as_deref().unwrap_or(""),
            status,
            route.category,
            route.handler
        );
    }

    let shutdown = gateway_worker.shutdown().await?;
    if shutdown.unflushed_mutations != 0 || shutdown.last_error.is_some() {
        return Err(format!("gateway audit worker did not shut down cleanly: {shutdown:?}").into());
    }
    Ok(())
}

async fn record_matched_path(request: Request, next: Next) -> Response {
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let mut response = next.run(request).await;
    if let Some(matched_path) = matched_path
        && let Ok(value) = HeaderValue::from_str(&matched_path)
    {
        response.headers_mut().insert(MATCHED_PATH_HEADER, value);
    }
    response
}

fn canonical_route_shape(path: &str) -> String {
    let segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if segment.starts_with('*') || segment.starts_with("{*") {
                "*"
            } else if segment.starts_with(':') || segment.starts_with('{') {
                ":"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn is_missing_response(status: StatusCode, body: &[u8]) -> bool {
    if status == StatusCode::METHOD_NOT_ALLOWED {
        return true;
    }
    if status == StatusCode::BAD_REQUEST {
        let body = String::from_utf8_lossy(body);
        if body.starts_with("Invalid URL:") || body.contains("Cannot parse") {
            return true;
        }
    }
    if status == StatusCode::NOT_FOUND {
        return serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|value| {
            value["error"]["type"] == "not_found_error"
                && value["error"]["message"] == "route not found"
        });
    }
    false
}

fn is_intentional_absence(method: &str, path: &str) -> bool {
    method == "POST" && path == "/setup/test-redis"
}
