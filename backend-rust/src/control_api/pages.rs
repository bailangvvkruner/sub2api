use std::{
    env,
    path::{Component, Path as FilePath, PathBuf},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use sqlx::PgPool;

use super::{
    models::{ApiEnvelope, ApiError},
    service::ControlApiState,
};

const MAX_PAGE_BYTES: u64 = 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024;

pub fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/pages", get(list_pages))
        .route("/api/v1/pages/{slug}", get(page_content))
        .route("/api/v1/pages/{slug}/images/{*filename}", get(page_image))
}

async fn page_content(
    State(state): State<ControlApiState>,
    headers: axum::http::HeaderMap,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    if !valid_slug(&slug) {
        return Err(ApiError::bad_request("Invalid page slug"));
    }
    let user = state.authenticate(&headers).await?;
    let Some(visibility) = slug_visibility(state.pool(), &slug).await? else {
        return Err(ApiError::not_found("Page not found"));
    };
    if visibility == "admin" && user.view.role != "admin" {
        return Err(ApiError::not_found("Page not found"));
    }

    let path = resolve_markdown(&pages_root(), &slug)
        .await
        .ok_or_else(|| ApiError::not_found("Page not found"))?;
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|error| ApiError::internal("read page metadata", error))?;
    if !metadata.is_file() {
        return Err(ApiError::not_found("Page not found"));
    }
    if metadata.len() > MAX_PAGE_BYTES {
        return Ok((StatusCode::PAYLOAD_TOO_LARGE, "page too large").into_response());
    }
    let content = tokio::fs::read(path)
        .await
        .map_err(|error| ApiError::internal("read page", error))?;
    let mut response = Response::new(Body::from(content));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/markdown; charset=utf-8"),
    );
    Ok(response)
}

async fn page_image(
    State(state): State<ControlApiState>,
    Path((slug, filename)): Path<(String, String)>,
) -> Response {
    if !valid_slug(&slug) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(Some(visibility)) = slug_visibility(state.pool(), &slug).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if visibility == "admin" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(path) = resolve_image(&pages_root(), &slug, &filename).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !metadata.is_file() || metadata.len() > MAX_IMAGE_BYTES {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(content) = tokio::fs::read(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mime = mime_infer::from_path(&path)
        .first_or_octet_stream()
        .essence_str()
        .to_owned();
    let mut response = Response::new(Body::from(content));
    if let Ok(value) = HeaderValue::from_str(&mime) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

async fn list_pages(
    State(state): State<ControlApiState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<String>>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    if user.view.role != "admin" {
        return Err(ApiError::forbidden(
            "Administrator access required",
            "ADMIN_REQUIRED",
        ));
    }
    let mut pages = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(pages_root()).await else {
        return Ok(Json(ApiEnvelope::success(pages)));
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::internal("list pages", error))?
    {
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("md") {
            continue;
        }
        let Some(slug) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if valid_slug(slug) {
            pages.push(slug.to_owned());
        }
    }
    pages.sort_unstable();
    Ok(Json(ApiEnvelope::success(pages)))
}

async fn slug_visibility(pool: &PgPool, slug: &str) -> Result<Option<String>, ApiError> {
    let raw = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'custom_menu_items'",
    )
    .fetch_optional(pool)
    .await?
    .unwrap_or_else(|| "[]".to_owned());
    let Ok(items) = serde_json::from_str::<Vec<PageMenuItem>>(&raw) else {
        return Ok(None);
    };
    Ok(items.into_iter().find_map(|item| {
        let item_slug = if item.page_slug.is_empty() {
            item.url.strip_prefix("md:").unwrap_or_default()
        } else {
            &item.page_slug
        };
        (item_slug == slug).then_some(item.visibility)
    }))
}

#[derive(Deserialize)]
struct PageMenuItem {
    #[serde(default)]
    url: String,
    #[serde(default)]
    page_slug: String,
    #[serde(default)]
    visibility: String,
}

fn pages_root() -> PathBuf {
    env::var_os("DATA_DIR")
        .map_or_else(|| PathBuf::from("data"), PathBuf::from)
        .join("pages")
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}

async fn resolve_markdown(root: &FilePath, slug: &str) -> Option<PathBuf> {
    let canonical_root = tokio::fs::canonicalize(root).await.ok()?;
    let candidate = root.join(format!("{slug}.md"));
    let canonical_target = tokio::fs::canonicalize(candidate).await.ok()?;
    (canonical_target != canonical_root && canonical_target.starts_with(&canonical_root))
        .then_some(canonical_target)
}

async fn resolve_image(root: &FilePath, slug: &str, filename: &str) -> Option<PathBuf> {
    let relative = safe_relative_path(filename)?;
    let canonical_root = tokio::fs::canonicalize(root).await.ok()?;
    let canonical_page = tokio::fs::canonicalize(root.join(slug)).await.ok()?;
    if canonical_page == canonical_root || !canonical_page.starts_with(&canonical_root) {
        return None;
    }
    let canonical_target = tokio::fs::canonicalize(canonical_page.join(relative))
        .await
        .ok()?;
    (canonical_target != canonical_page && canonical_target.starts_with(&canonical_page))
        .then_some(canonical_target)
}

fn safe_relative_path(filename: &str) -> Option<PathBuf> {
    if filename.is_empty()
        || filename.starts_with(['/', '\\'])
        || filename.contains('\\')
        || filename.contains('\0')
    {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in FilePath::new(filename).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_slugs_and_image_paths() {
        assert!(valid_slug("guide-1_en"));
        assert!(!valid_slug("-guide"));
        assert!(!valid_slug("../guide"));
        assert_eq!(
            safe_relative_path("images/logo.png"),
            Some(PathBuf::from("images/logo.png"))
        );
        assert_eq!(
            safe_relative_path("./logo.png"),
            Some(PathBuf::from("logo.png"))
        );
        assert!(safe_relative_path("../secret.png").is_none());
        assert!(safe_relative_path("images\\secret.png").is_none());
        assert!(safe_relative_path("/etc/passwd").is_none());
        assert!(safe_relative_path("logo.png\0").is_none());
    }

    #[tokio::test]
    async fn canonical_resolution_rejects_paths_outside_the_page_root() {
        let root = env::temp_dir().join(format!("sub2api-pages-{}", uuid::Uuid::new_v4()));
        let page = root.join("guide");
        tokio::fs::create_dir_all(&page).await.unwrap();
        tokio::fs::write(root.join("guide.md"), b"# Guide")
            .await
            .unwrap();
        tokio::fs::write(page.join("logo.png"), b"image")
            .await
            .unwrap();
        assert!(resolve_markdown(&root, "guide").await.is_some());
        assert!(resolve_image(&root, "guide", "logo.png").await.is_some());
        assert!(resolve_image(&root, "guide", "../guide.md").await.is_none());
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn canonical_resolution_rejects_symlink_escape() {
        let root = env::temp_dir().join(format!("sub2api-pages-{}", uuid::Uuid::new_v4()));
        let page = root.join("guide");
        let outside =
            env::temp_dir().join(format!("sub2api-pages-outside-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&page).await.unwrap();
        tokio::fs::create_dir_all(&outside).await.unwrap();
        tokio::fs::write(outside.join("secret.png"), b"secret")
            .await
            .unwrap();
        if !create_directory_symlink(&outside, &page.join("images")) {
            tokio::fs::remove_dir_all(root).await.unwrap();
            tokio::fs::remove_dir_all(outside).await.unwrap();
            return;
        }
        assert!(
            resolve_image(&root, "guide", "images/secret.png")
                .await
                .is_none()
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
        tokio::fs::remove_dir_all(outside).await.unwrap();
    }

    #[cfg(unix)]
    fn create_directory_symlink(target: &FilePath, link: &FilePath) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn create_directory_symlink(target: &FilePath, link: &FilePath) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }
}
