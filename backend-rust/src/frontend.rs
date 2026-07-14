use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::{RngCore, rngs::OsRng};
use url::Url;

use crate::control_api::ControlApiState;

pub(crate) const DEFAULT_CSP_POLICY: &str = "default-src 'self'; script-src 'self' __CSP_NONCE__ https://challenges.cloudflare.com https://static.cloudflareinsights.com https://*.stripe.com https://static.airwallex.com https://checkout.airwallex.com https://static-demo.airwallex.com https://checkout-demo.airwallex.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://static.airwallex.com https://checkout.airwallex.com https://static-demo.airwallex.com https://checkout-demo.airwallex.com; img-src 'self' data: blob: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https:; frame-src https://challenges.cloudflare.com https://*.stripe.com https://checkout.airwallex.com https://checkout-demo.airwallex.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

#[derive(Clone)]
pub struct FrontendAssets {
    root: Arc<PathBuf>,
    control: Option<ControlApiState>,
}

impl FrontendAssets {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Arc::new(root.into()),
            control: None,
        }
    }

    #[must_use]
    pub fn with_public_settings(mut self, control: ControlApiState) -> Self {
        self.control = Some(control);
        self
    }

    /// Serves a static asset or the SPA entry point. API-like paths are never
    /// converted into HTML responses.
    pub async fn try_serve(&self, request_path: &str) -> Option<Response> {
        if is_backend_path(request_path) {
            return None;
        }
        let relative = safe_relative_path(request_path)?;
        let requested = self.root.join(&relative);
        let (path, is_index) = if is_file(&requested).await {
            (requested, relative == Path::new("index.html"))
        } else {
            (self.root.join("index.html"), true)
        };
        let mut bytes = tokio::fs::read(&path).await.ok()?;
        let mut csp = None;
        if is_index {
            let nonce = generate_nonce();
            let mut frame_origins = Vec::new();
            let mut settings_json = None;
            if let Some(control) = &self.control
                && let Ok(settings) = control.public_settings().await
            {
                frame_origins = csp_frame_origins(&settings);
                if let Ok(json) = serde_json::to_string(&settings) {
                    settings_json = Some(json);
                }
            }
            bytes = inject_script_nonce(&bytes, nonce.as_deref());
            if let Some(json) = settings_json {
                bytes = inject_public_settings(&bytes, &json, nonce.as_deref());
            }
            csp = Some(csp_policy(nonce.as_deref(), &frame_origins));
        }
        let mime = mime_infer::from_path(&path)
            .first_or_octet_stream()
            .to_string();
        let mut response = Response::new(Body::from(bytes));
        *response.status_mut() = StatusCode::OK;
        if let Ok(content_type) = HeaderValue::from_str(&mime) {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control(&relative, is_index)),
        );
        if let Some(csp) = csp
            && let Ok(value) = HeaderValue::from_str(&csp)
        {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, value);
        }
        Some(response)
    }
}

fn inject_public_settings(html: &[u8], settings_json: &str, nonce: Option<&str>) -> Vec<u8> {
    let safe_json = settings_json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let nonce = nonce.map_or_else(String::new, |value| format!(" nonce=\"{value}\""));
    let script = format!("<script{nonce}>window.__APP_CONFIG__={safe_json};</script>");
    let marker = b"</head>";
    let Some(position) = html
        .windows(marker.len())
        .position(|window| window == marker)
    else {
        return html.to_vec();
    };
    let mut rendered = Vec::with_capacity(html.len() + script.len());
    rendered.extend_from_slice(&html[..position]);
    rendered.extend_from_slice(script.as_bytes());
    rendered.extend_from_slice(&html[position..]);
    rendered
}

fn inject_script_nonce(html: &[u8], nonce: Option<&str>) -> Vec<u8> {
    let Some(nonce) = nonce else {
        return html.to_vec();
    };
    let Ok(html) = std::str::from_utf8(html) else {
        return html.to_vec();
    };
    let mut rendered = String::with_capacity(html.len() + nonce.len() * 2);
    let mut cursor = 0;
    while let Some(relative_start) = html[cursor..].find("<script") {
        let start = cursor + relative_start;
        let attributes_start = start + "<script".len();
        let Some(next) = html.as_bytes().get(attributes_start) else {
            break;
        };
        if *next != b'>' && !next.is_ascii_whitespace() {
            rendered.push_str(&html[cursor..attributes_start]);
            cursor = attributes_start;
            continue;
        }
        let Some(relative_end) = html[attributes_start..].find('>') else {
            break;
        };
        let end = attributes_start + relative_end;
        rendered.push_str(&html[cursor..attributes_start]);
        let tag = &html[attributes_start..end];
        if !has_nonce_attribute(tag) {
            write!(&mut rendered, " nonce=\"{nonce}\"")
                .expect("writing a nonce to a String cannot fail");
        }
        rendered.push_str(tag);
        rendered.push('>');
        cursor = end + 1;
    }
    rendered.push_str(&html[cursor..]);
    rendered.into_bytes()
}

fn has_nonce_attribute(attributes: &str) -> bool {
    let lower = attributes.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    bytes.windows(5).enumerate().any(|(index, window)| {
        window == b"nonce"
            && index
                .checked_sub(1)
                .and_then(|previous| bytes.get(previous))
                .is_some_and(u8::is_ascii_whitespace)
            && bytes
                .get(index + 5)
                .is_some_and(|next| next.is_ascii_whitespace() || *next == b'=')
    })
}

fn cache_control(relative: &Path, is_index: bool) -> &'static str {
    if is_index {
        "no-cache"
    } else if relative.starts_with(Path::new("assets")) {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    }
}

fn generate_nonce() -> Option<String> {
    let mut bytes = [0_u8; 16];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(STANDARD.encode(bytes))
}

fn csp_policy(nonce: Option<&str>, frame_origins: &[String]) -> String {
    let nonce = nonce.map_or("'unsafe-inline'".to_owned(), |value| {
        format!("'nonce-{value}'")
    });
    let mut policy = DEFAULT_CSP_POLICY.replace("__CSP_NONCE__", &nonce);
    if !frame_origins.is_empty() {
        let additions = format!(" {}", frame_origins.join(" "));
        if let Some(index) = policy.find("frame-src ")
            && let Some(end) = policy[index..].find(';')
        {
            policy.insert_str(index + end, &additions);
        }
    }
    policy
}

fn csp_frame_origins(settings: &crate::control_api::PublicSettings) -> Vec<String> {
    let mut values = vec![settings.home_content.as_str()];
    if settings.purchase_subscription_enabled {
        values.push(settings.purchase_subscription_url.as_str());
    }
    values.extend(
        settings
            .custom_menu_items
            .iter()
            .map(|item| item.url.as_str()),
    );
    let mut origins = Vec::new();
    for value in values {
        let Ok(url) = Url::parse(value.trim()) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        let origin = url.origin().ascii_serialization();
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    origins
}

fn safe_relative_path(request_path: &str) -> Option<PathBuf> {
    let trimmed = request_path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(PathBuf::from("index.html"));
    }
    let mut path = PathBuf::new();
    for segment in trimmed.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") || segment.contains('\\') {
            return None;
        }
        path.push(segment);
    }
    Some(path)
}

fn is_backend_path(path: &str) -> bool {
    let path = path.trim();
    path == "/health"
        || path == "/ready"
        || path == "/responses"
        || path.starts_with("/responses/")
        || path.starts_with("/api/")
        || path.starts_with("/v1/")
        || path.starts_with("/v1beta/")
        || path.starts_with("/backend-api/")
        || path.starts_with("/antigravity/")
        || path.starts_with("/setup/")
        || path.starts_with("/chat/")
        || path.starts_with("/embeddings")
        || path.starts_with("/images/")
        || path.starts_with("/videos/")
}

async fn is_file(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .is_ok_and(|metadata| metadata.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        assert!(safe_relative_path("/../secret").is_none());
        assert!(safe_relative_path("/assets/../../secret").is_none());
        assert!(safe_relative_path("/assets\\secret").is_none());
    }

    #[test]
    fn backend_paths_never_fall_back_to_spa() {
        for path in [
            "/api/v1/auth/login",
            "/v1/messages",
            "/v1beta/models/gemini:generateContent",
            "/responses",
            "/setup/status",
        ] {
            assert!(is_backend_path(path), "{path} must bypass frontend");
        }
        assert!(!is_backend_path("/admin/accounts"));
    }

    #[test]
    fn settings_injection_cannot_close_the_script() {
        let html = b"<html><head></head></html>";
        let rendered = inject_public_settings(html, r#"{"site_name":"</script>"}"#, Some("nonce"));
        let rendered = String::from_utf8(rendered).expect("HTML remains UTF-8");
        assert!(rendered.contains("\\u003c/script\\u003e"));
        assert_eq!(rendered.matches("</script>").count(), 1);
        assert!(rendered.contains("nonce=\"nonce\""));
    }

    #[test]
    fn nonce_is_applied_to_vite_scripts_and_csp() {
        let html = br#"<script type="module" src="/assets/app.js"></script>"#;
        let rendered = String::from_utf8(inject_script_nonce(html, Some("abc"))).unwrap();
        assert!(rendered.contains("<script nonce=\"abc\" type=\"module\""));
        let policy = csp_policy(Some("abc"), &["https://portal.example".to_owned()]);
        assert!(policy.contains("script-src 'self' 'nonce-abc'"));
        assert!(policy.contains("https://portal.example;"));
    }

    #[test]
    fn nonce_is_applied_once_and_existing_nonce_is_preserved() {
        let html = br#"<script></script><script type="module"></script><script nonce="existing"></script>"#;
        let rendered = String::from_utf8(inject_script_nonce(html, Some("abc"))).unwrap();
        assert_eq!(rendered.matches("nonce=\"abc\"").count(), 2);
        assert_eq!(rendered.matches("nonce=\"existing\"").count(), 1);
        assert!(!rendered.contains("nonce=\"abc\" nonce="));
    }

    #[test]
    fn immutable_caching_is_limited_to_built_assets() {
        assert_eq!(
            cache_control(Path::new("assets/app-HASH.js"), false),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(
            cache_control(Path::new("manifest.webmanifest"), false),
            "public, max-age=3600"
        );
        assert_eq!(cache_control(Path::new("index.html"), true), "no-cache");
    }
}
