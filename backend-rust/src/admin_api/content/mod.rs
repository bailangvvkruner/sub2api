mod announcements;
mod channels;
mod monitors;
mod shared;
mod templates;

use axum::Router;

use super::http::AdminApiState;

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .merge(announcements::router())
        .merge(channels::router())
        .merge(monitors::router())
        .merge(templates::router())
}
