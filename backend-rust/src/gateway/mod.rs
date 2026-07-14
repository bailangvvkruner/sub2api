//! Protocol-neutral building blocks for forwarding supported AI API requests.
//!
//! This module intentionally does not own account selection, billing, retries,
//! or an HTTP client. Those layers can build a request from these plans and
//! keep the returned stream opaque while forwarding it to Axum.

mod adapters;
mod error;
mod invalidation;
mod moderation;
mod rectifier;
mod request;
mod response;
mod route;
mod runtime_authority;
mod runtime_policy;
mod service;
mod tls_fingerprint;
mod transform;
mod upstream;
mod web_search;

pub use error::{GatewayError, GatewayErrorKind};
pub use invalidation::{
    AuthCacheInvalidationShutdownError, AuthCacheInvalidationWorker, AuthCacheInvalidator,
    GatewayAuthState,
};
pub use request::{RequestBodyError, RequestMetadata, inspect_request};
pub use response::{
    ClientResponsePlan, PassthroughBody, ResponseMode, UpstreamResponse, prepare_passthrough,
    response_mode_from_headers,
};
pub use route::{GatewayRoute, Protocol, RouteKind, classify_route};
pub use service::{
    GatewayPendingBillingSnapshot, GatewayRuntime, GatewayRuntimeBuildError, GatewayRuntimeConfig,
    GatewayWriteShutdownError, GatewayWriteShutdownReport, GatewayWriteWorker,
};
pub use upstream::{
    Credential, UpstreamBuildError, UpstreamRequestPlan, build_upstream_headers,
    build_upstream_request, build_upstream_url,
};
