use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use async_trait::async_trait;
use reqwest::{
    Client, ClientBuilder, RequestBuilder,
    header::{ACCEPT, AUTHORIZATION, HeaderName, HeaderValue},
    redirect::Policy,
};
use serde_json::{Value, json};
use tokio::time::Instant;
use url::Url;

use super::models::{
    AccountProbe, ProbeAccount, ProbeProxy, ProbeRequest, ProbeResult, ValidatedProbeTarget,
};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug)]
pub struct ReqwestAccountProbeConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ReqwestAccountProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReqwestAccountProbe {
    config: ReqwestAccountProbeConfig,
}

impl ReqwestAccountProbe {
    #[must_use]
    pub const fn with_config(config: ReqwestAccountProbeConfig) -> Self {
        Self { config }
    }

    fn build_client(
        &self,
        targets: &[ValidatedProbeTarget],
        proxy: Option<&ProbeProxy>,
    ) -> Result<Client, String> {
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout)
            .user_agent("sub2api-rust/account-probe");

        for target in targets {
            builder = pin_validated_target(builder, target)?;
        }
        if let Some(proxy) = proxy {
            validate_proxy_binding(proxy)?;
            builder = pin_validated_target(builder, proxy.validated_target())?;
            let proxy_url = build_proxy_url(proxy)?;
            let configured = reqwest::Proxy::all(proxy_url.as_str())
                .map_err(|_| "account proxy configuration is invalid".to_owned())?;
            builder = builder.proxy(configured);
        }

        builder
            .build()
            .map_err(|_| "account probe client could not be initialized".to_owned())
    }
}

#[async_trait]
impl AccountProbe for ReqwestAccountProbe {
    async fn probe(&self, request: ProbeRequest) -> Result<ProbeResult, String> {
        let target = request
            .validated_targets
            .first()
            .ok_or_else(|| "account has no supported probe target".to_owned())?;
        let target_url = parse_probe_url(target)?;
        let client = self.build_client(&request.validated_targets, request.proxy.as_ref())?;
        let outbound = authenticated_request(client.get(target_url), &request.account)?;

        let started = Instant::now();
        let response = outbound
            .send()
            .await
            .map_err(|error| redacted_request_error(&error))?;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let status = response.status();
        let mut metadata = BTreeMap::from([
            ("http_status".to_owned(), json!(status.as_u16())),
            ("latency_ms".to_owned(), json!(elapsed_ms)),
        ]);
        metadata.insert(
            "platform".to_owned(),
            Value::String(request.account.platform.trim().to_ascii_lowercase()),
        );

        let (success, message) = if status.is_success() {
            (true, "account connection succeeded".to_owned())
        } else if matches!(status.as_u16(), 401 | 403) {
            (
                false,
                format!("upstream authentication was rejected (HTTP {status})"),
            )
        } else if status.is_redirection() {
            (
                false,
                format!("upstream redirected the probe (HTTP {status})"),
            )
        } else {
            (
                false,
                format!("upstream returned an unsuccessful response (HTTP {status})"),
            )
        };

        Ok(ProbeResult {
            success,
            message,
            metadata,
        })
    }
}

fn parse_probe_url(target: &ValidatedProbeTarget) -> Result<Url, String> {
    if target.resolved_addresses().is_empty() {
        return Err("account probe target has no validated address".to_owned());
    }
    let url = Url::parse(target.url()).map_err(|_| "account probe target is invalid".to_owned())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("account probe target is invalid".to_owned());
    }
    Ok(url)
}

fn pin_validated_target(
    builder: ClientBuilder,
    target: &ValidatedProbeTarget,
) -> Result<ClientBuilder, String> {
    let url = parse_probe_url(target)?;
    let host = url
        .host_str()
        .ok_or_else(|| "account probe target is invalid".to_owned())?;
    if host.parse::<IpAddr>().is_ok() {
        return Ok(builder);
    }
    Ok(builder.resolve_to_addrs(host, target.resolved_addresses()))
}

fn authenticated_request(
    request: RequestBuilder,
    account: &ProbeAccount,
) -> Result<RequestBuilder, String> {
    let platform = account.platform.trim().to_ascii_lowercase();
    let account_type = account.account_type.trim().to_ascii_lowercase();
    let api_key = account_credential(account, &["api_key", "apiKey"]);
    let bearer = account_credential(
        account,
        &["access_token", "accessToken", "auth_token", "token"],
    );
    let mut request = request.header(ACCEPT, "application/json");

    match platform.as_str() {
        "anthropic" if is_api_key_account(&account_type) => {
            let token = api_key
                .or(bearer)
                .ok_or_else(|| "account has no usable probe credential".to_owned())?;
            if anthropic_uses_bearer(account) {
                request = bearer_request(request, token)?;
            } else {
                request = secret_header(request, "x-api-key", token)?;
            }
            request = request.header("anthropic-version", "2023-06-01");
        }
        "gemini" if api_key.is_some() && is_api_key_account(&account_type) => {
            request = secret_header(
                request,
                "x-goog-api-key",
                api_key.expect("the API key presence was checked"),
            )?;
        }
        _ => {
            let token = bearer
                .or(api_key)
                .ok_or_else(|| "account has no usable probe credential".to_owned())?;
            request = bearer_request(request, token)?;
        }
    }

    Ok(request)
}

fn is_api_key_account(account_type: &str) -> bool {
    matches!(account_type, "apikey" | "api_key" | "upstream")
}

fn account_credential<'a>(account: &'a ProbeAccount, keys: &[&str]) -> Option<&'a str> {
    [&account.credentials, &account.extra]
        .into_iter()
        .find_map(|value| {
            keys.iter().find_map(|key| {
                value
                    .get(*key)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
        })
}

fn anthropic_uses_bearer(account: &ProbeAccount) -> bool {
    [&account.extra, &account.credentials]
        .into_iter()
        .filter_map(|value| value.get("anthropic_apikey_auth_scheme"))
        .filter_map(Value::as_str)
        .any(|value| value.trim() == "authorization_bearer")
}

fn bearer_request(request: RequestBuilder, token: &str) -> Result<RequestBuilder, String> {
    let value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "account probe credential is invalid".to_owned())?;
    Ok(request.header(AUTHORIZATION, value))
}

fn secret_header(
    request: RequestBuilder,
    name: &'static str,
    secret: &str,
) -> Result<RequestBuilder, String> {
    let name = HeaderName::from_static(name);
    let value = HeaderValue::from_str(secret)
        .map_err(|_| "account probe credential is invalid".to_owned())?;
    Ok(request.header(name, value))
}

fn validate_proxy_binding(proxy: &ProbeProxy) -> Result<(), String> {
    let validated = parse_probe_url(proxy.validated_target())?;
    let validated_host = validated
        .host_str()
        .ok_or_else(|| "account proxy configuration is invalid".to_owned())?;
    if normalize_host(validated_host) != normalize_host(proxy.host())
        || validated.port_or_known_default() != Some(proxy.port())
    {
        return Err("account proxy validation does not match its configuration".to_owned());
    }
    Ok(())
}

fn build_proxy_url(proxy: &ProbeProxy) -> Result<Url, String> {
    let protocol = proxy.protocol().trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err("account proxy protocol is unsupported".to_owned());
    }
    let mut url = Url::parse(&format!("{protocol}://localhost"))
        .map_err(|_| "account proxy configuration is invalid".to_owned())?;
    let host = proxy.host().trim();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    url.set_host(Some(&host))
        .map_err(|_| "account proxy configuration is invalid".to_owned())?;
    url.set_port(Some(proxy.port()))
        .map_err(|()| "account proxy configuration is invalid".to_owned())?;
    if let Some(username) = proxy.username().filter(|value| !value.is_empty()) {
        url.set_username(username)
            .map_err(|()| "account proxy configuration is invalid".to_owned())?;
        if let Some(password) = proxy.password() {
            url.set_password(Some(password))
                .map_err(|()| "account proxy configuration is invalid".to_owned())?;
        }
    }
    Ok(url)
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn redacted_request_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "account probe timed out".to_owned()
    } else if error.is_connect() {
        "account probe connection failed".to_owned()
    } else {
        "account probe request failed".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn account(platform: &str, account_type: &str, credentials: Value) -> ProbeAccount {
        ProbeAccount {
            id: 17,
            platform: platform.to_owned(),
            account_type: account_type.to_owned(),
            credentials,
            extra: json!({}),
        }
    }

    fn target(url: String, address: SocketAddr) -> ValidatedProbeTarget {
        ValidatedProbeTarget::new(url, vec![address])
    }

    async fn capture_one_request(listener: TcpListener, status: &str) -> String {
        let (mut stream, _) = listener.accept().await.expect("request should connect");
        let mut buffer = vec![0_u8; 16 * 1024];
        let read = stream
            .read(&mut buffer)
            .await
            .expect("request should be readable");
        stream
            .write_all(
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("response should be writable");
        String::from_utf8(buffer[..read].to_vec()).expect("HTTP request should be text")
    }

    #[tokio::test]
    async fn probe_pins_dns_and_sends_platform_authentication() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        let capture = tokio::spawn(capture_one_request(listener, "200 OK"));
        let secret = "probe-api-key-super-secret";
        let target_url = format!(
            "http://account-probe.invalid:{}/v1/models?private=target-secret",
            address.port()
        );
        let request = ProbeRequest {
            account: account("openai", "apikey", json!({ "api_key": secret })),
            validated_targets: vec![target(target_url.clone(), address)],
            proxy: None,
        };

        let result = ReqwestAccountProbe::default()
            .probe(request)
            .await
            .expect("probe should complete");
        let captured = capture.await.expect("capture task should complete");

        assert!(result.success);
        assert!(captured.starts_with("GET /v1/models?private=target-secret HTTP/1.1"));
        assert!(
            captured
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {secret}"))
        );
        let public_result = serde_json::to_string(&result).expect("result should serialize");
        assert!(!public_result.contains(secret));
        assert!(!public_result.contains(&target_url));
        assert!(!public_result.contains("target-secret"));
    }

    #[tokio::test]
    async fn http_proxy_is_pinned_and_used_without_leaking_configuration() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("proxy listener should bind");
        let proxy_address = listener
            .local_addr()
            .expect("proxy listener should have address");
        let capture = tokio::spawn(capture_one_request(listener, "204 No Content"));
        let upstream = target(
            "http://upstream-probe.invalid/v1/models?private=upstream-target".to_owned(),
            SocketAddr::from(([203, 0, 113, 10], 80)),
        );
        let proxy_target = target(
            format!("http://proxy-probe.invalid:{}", proxy_address.port()),
            proxy_address,
        );
        let proxy = ProbeProxy::new(
            "http".to_owned(),
            "proxy-probe.invalid".to_owned(),
            proxy_address.port(),
            Some("proxy-user".to_owned()),
            Some("proxy-password-secret".to_owned()),
            proxy_target,
        );
        let request = ProbeRequest {
            account: account(
                "anthropic",
                "apikey",
                json!({ "api_key": "anthropic-secret" }),
            ),
            validated_targets: vec![upstream],
            proxy: Some(proxy),
        };

        let result = ReqwestAccountProbe::default()
            .probe(request)
            .await
            .expect("proxied probe should complete");
        let captured = capture.await.expect("capture task should complete");

        assert!(result.success);
        assert!(captured.starts_with(
            "GET http://upstream-probe.invalid/v1/models?private=upstream-target HTTP/1.1"
        ));
        let public_result = serde_json::to_string(&result).expect("result should serialize");
        assert!(!public_result.contains("anthropic-secret"));
        assert!(!public_result.contains("proxy-password-secret"));
        assert!(!public_result.contains("upstream-target"));
    }

    #[tokio::test]
    async fn request_errors_and_debug_output_are_redacted() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("temporary listener should bind");
        let address = listener.local_addr().expect("listener should have address");
        drop(listener);
        let secret = "credential-that-must-not-leak";
        let target_url = format!(
            "http://unreachable-probe.invalid:{}/private-target?token=url-secret",
            address.port()
        );
        let request = ProbeRequest {
            account: account("gemini", "apikey", json!({ "api_key": secret })),
            validated_targets: vec![target(target_url.clone(), address)],
            proxy: None,
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains(&target_url));
        assert!(!debug.contains("url-secret"));

        let error = ReqwestAccountProbe::default()
            .probe(request)
            .await
            .expect_err("closed listener should reject the probe");
        assert!(!error.contains(secret));
        assert!(!error.contains(&target_url));
        assert!(!error.contains("url-secret"));
    }

    #[test]
    fn proxy_url_supports_http_and_socks_credentials() {
        let validated = target(
            "http://proxy.example:1080".to_owned(),
            SocketAddr::from(([203, 0, 113, 11], 1080)),
        );
        let proxy = ProbeProxy::new(
            "socks5".to_owned(),
            "proxy.example".to_owned(),
            1080,
            Some("user@example".to_owned()),
            Some("p@ss/word".to_owned()),
            validated,
        );

        assert_eq!(
            build_proxy_url(&proxy)
                .expect("SOCKS proxy should build")
                .as_str(),
            "socks5://user%40example:p%40ss%2Fword@proxy.example:1080"
        );
    }
}
