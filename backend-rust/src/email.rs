use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sqlx::{PgPool, Row};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

use crate::control_api::AuthNotifier;

const SMTP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const SMTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SMTP_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct PostgresSmtpNotifier {
    pool: PgPool,
    tls: TlsConnector,
}

impl PostgresSmtpNotifier {
    /// Builds an SMTP notifier with the bundled public TLS trust roots.
    ///
    /// # Errors
    ///
    /// Returns an error if the selected crypto provider cannot support the
    /// default TLS protocol versions.
    pub fn new(pool: PgPool) -> Result<Self, String> {
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("configure SMTP TLS protocol versions: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            pool,
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    async fn load_settings(&self) -> Result<HashMap<String, String>, String> {
        let rows = sqlx::query(
            r"
SELECT key, value
FROM settings
WHERE key = ANY($1)
",
        )
        .bind(
            &[
                "smtp_host",
                "smtp_port",
                "smtp_username",
                "smtp_password",
                "smtp_from",
                "smtp_from_email",
                "smtp_from_name",
                "smtp_use_tls",
                "site_name",
                "site_url",
                "api_base_url",
            ][..],
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| format!("load SMTP settings: {error}"))?;
        let mut values = HashMap::with_capacity(rows.len());
        for row in rows {
            let key: String = row
                .try_get("key")
                .map_err(|error| format!("decode SMTP setting key: {error}"))?;
            let value: String = row
                .try_get("value")
                .map_err(|error| format!("decode SMTP setting value: {error}"))?;
            values.insert(key, value);
        }
        Ok(values)
    }

    async fn load_config(&self) -> Result<SmtpConfig, String> {
        SmtpConfig::from_settings(&self.load_settings().await?)
    }

    async fn deliver(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let config = self.load_config().await?;
        send_smtp(&self.tls, &config, to, subject, body).await
    }

    /// Sends an already-rendered HTML notification with the persisted SMTP
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid SMTP settings, an invalid recipient or
    /// subject, connection/TLS/authentication failures, or a delivery timeout.
    pub async fn send_html(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        self.deliver(to, subject, body).await
    }

    /// Tests an SMTP connection using request overrides with persisted-setting fallback.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid settings, connection/TLS/authentication failures,
    /// or an SMTP timeout.
    pub async fn test_connection(&self, payload: &Value) -> Result<(), String> {
        let mut values = self.load_settings().await?;
        apply_smtp_overrides(&mut values, payload);
        if !values.contains_key("smtp_from") && !values.contains_key("smtp_from_email") {
            values.insert(
                "smtp_from".to_owned(),
                values
                    .get("smtp_username")
                    .filter(|value| valid_mailbox(value))
                    .cloned()
                    .unwrap_or_else(|| "smtp-probe@localhost.invalid".to_owned()),
            );
        }
        let config = SmtpConfig::from_settings(&values)?;
        probe_smtp(&self.tls, &config).await
    }

    /// Sends the administrator SMTP test message using request overrides.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid settings/recipient input or SMTP delivery failure.
    pub async fn send_test_email(&self, payload: &Value) -> Result<(), String> {
        let recipient = payload
            .get("email")
            .and_then(Value::as_str)
            .ok_or_else(|| "test email recipient is required".to_owned())?;
        let mut values = self.load_settings().await?;
        apply_smtp_overrides(&mut values, payload);
        let config = SmtpConfig::from_settings(&values)?;
        let body = format!(
            "<!doctype html><html><body><h1>{}</h1><p>Email configuration successful.</p><p>This is an automated SMTP test message.</p></body></html>",
            escape_html(&config.site_name)
        );
        send_smtp(
            &self.tls,
            &config,
            recipient,
            &format!("[{}] Test email", config.site_name),
            &body,
        )
        .await
    }
}

#[async_trait]
impl AuthNotifier for PostgresSmtpNotifier {
    async fn send_verification_code(&self, email: &str, code: &str) -> Result<(), String> {
        let config = self.load_config().await?;
        let body = format!(
            "<!doctype html><html><body><h1>{}</h1><p>Your verification code is:</p><p style=\"font-size:32px;font-weight:bold;letter-spacing:6px\">{}</p><p>This code expires in 10 minutes.</p></body></html>",
            escape_html(&config.site_name),
            escape_html(code)
        );
        send_smtp(
            &self.tls,
            &config,
            email,
            &format!("[{}] Email verification code", config.site_name),
            &body,
        )
        .await
    }

    async fn send_password_reset(&self, email: &str, token: &str) -> Result<(), String> {
        let config = self.load_config().await?;
        let base = config
            .site_url
            .trim_end_matches('/')
            .trim_end_matches("/api");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("email", email)
            .append_pair("token", token)
            .finish();
        let reset_url = format!("{base}/reset-password?{query}");
        let body = format!(
            "<!doctype html><html><body><h1>{}</h1><p>A password reset was requested for this account.</p><p><a href=\"{}\">Reset password</a></p><p>This link expires in 30 minutes.</p></body></html>",
            escape_html(&config.site_name),
            escape_html(&reset_url)
        );
        self.deliver(
            email,
            &format!("[{}] Reset your password", config.site_name),
            &body,
        )
        .await
    }
}

#[derive(Clone, Debug)]
struct SmtpConfig {
    host: String,
    port: u16,
    username: String,
    password: String,
    from: String,
    from_name: String,
    use_tls: bool,
    site_name: String,
    site_url: String,
}

impl SmtpConfig {
    fn from_settings(values: &HashMap<String, String>) -> Result<Self, String> {
        let get = |key: &str| values.get(key).map_or("", String::as_str).trim();
        let host = get("smtp_host");
        if host.is_empty() || contains_newline(host) {
            return Err("SMTP is not configured".to_owned());
        }
        let port = match get("smtp_port") {
            "" => 587,
            value => value
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| "SMTP port is invalid".to_owned())?,
        };
        let username = get("smtp_username").to_owned();
        let password = get("smtp_password").to_owned();
        let from = [get("smtp_from"), get("smtp_from_email"), &username]
            .into_iter()
            .find(|value| !value.is_empty())
            .unwrap_or_default()
            .to_owned();
        if !valid_mailbox(&from) {
            return Err("SMTP sender address is invalid".to_owned());
        }
        let site_url = [get("site_url"), get("api_base_url")]
            .into_iter()
            .find(|value| !value.is_empty())
            .unwrap_or("/")
            .to_owned();
        let site_name = strip_header_controls(get("site_name"));
        Ok(Self {
            host: host.to_owned(),
            port,
            username,
            password,
            from,
            from_name: strip_header_controls(get("smtp_from_name")),
            use_tls: get("smtp_use_tls").eq_ignore_ascii_case("true"),
            site_name: if site_name.is_empty() {
                "Sub2API".to_owned()
            } else {
                site_name
            },
            site_url,
        })
    }
}

fn apply_smtp_overrides(values: &mut HashMap<String, String>, payload: &Value) {
    for key in [
        "smtp_host",
        "smtp_username",
        "smtp_password",
        "smtp_from_email",
        "smtp_from_name",
    ] {
        if let Some(value) = payload.get(key).and_then(Value::as_str)
            && (!value.trim().is_empty() || key != "smtp_password")
        {
            values.insert(key.to_owned(), value.trim().to_owned());
        }
    }
    if let Some(port) = payload.get("smtp_port").and_then(Value::as_u64) {
        values.insert("smtp_port".to_owned(), port.to_string());
    }
    if let Some(use_tls) = payload.get("smtp_use_tls").and_then(Value::as_bool) {
        values.insert("smtp_use_tls".to_owned(), use_tls.to_string());
    }
}

async fn probe_smtp(connector: &TlsConnector, config: &SmtpConfig) -> Result<(), String> {
    timeout(SMTP_OPERATION_TIMEOUT, probe_smtp_inner(connector, config))
        .await
        .map_err(|_| "SMTP operation timed out".to_owned())?
}

async fn probe_smtp_inner(connector: &TlsConnector, config: &SmtpConfig) -> Result<(), String> {
    let address = format!("{}:{}", config.host, config.port);
    let tcp = timeout(SMTP_DIAL_TIMEOUT, TcpStream::connect(&address))
        .await
        .map_err(|_| "SMTP connection timed out".to_owned())?
        .map_err(|error| format!("connect to SMTP server: {error}"))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("configure SMTP socket: {error}"))?;
    if config.use_tls {
        let mut stream = connect_tls(connector, &config.host, tcp).await?;
        smtp_greeting(&mut stream).await?;
        let _ = smtp_ehlo(&mut stream).await?;
        smtp_auth_and_quit(&mut stream, config).await
    } else {
        let mut stream = tcp;
        smtp_greeting(&mut stream).await?;
        let capabilities = smtp_ehlo(&mut stream).await?;
        if capabilities
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case("STARTTLS"))
        {
            expect_response(&mut stream, "STARTTLS", &[220]).await?;
            let mut stream = connect_tls(connector, &config.host, stream).await?;
            let _ = smtp_ehlo(&mut stream).await?;
            smtp_auth_and_quit(&mut stream, config).await
        } else {
            smtp_auth_and_quit(&mut stream, config).await
        }
    }
}

async fn send_smtp(
    connector: &TlsConnector,
    config: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    if !valid_mailbox(to) {
        return Err("recipient email address is invalid".to_owned());
    }
    if contains_newline(subject) {
        return Err("email subject contains invalid characters".to_owned());
    }
    timeout(
        SMTP_OPERATION_TIMEOUT,
        send_smtp_inner(connector, config, to, subject, body),
    )
    .await
    .map_err(|_| "SMTP operation timed out".to_owned())?
}

async fn send_smtp_inner(
    connector: &TlsConnector,
    config: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let address = format!("{}:{}", config.host, config.port);
    let tcp = timeout(SMTP_DIAL_TIMEOUT, TcpStream::connect(&address))
        .await
        .map_err(|_| "SMTP connection timed out".to_owned())?
        .map_err(|error| format!("connect to SMTP server: {error}"))?;
    tcp.set_nodelay(true)
        .map_err(|error| format!("configure SMTP socket: {error}"))?;

    if config.use_tls {
        let mut stream = connect_tls(connector, &config.host, tcp).await?;
        smtp_greeting(&mut stream).await?;
        let _ = smtp_ehlo(&mut stream).await?;
        smtp_transaction(&mut stream, config, to, subject, body).await
    } else {
        let mut stream = tcp;
        smtp_greeting(&mut stream).await?;
        let capabilities = smtp_ehlo(&mut stream).await?;
        if capabilities
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case("STARTTLS"))
        {
            expect_response(&mut stream, "STARTTLS", &[220]).await?;
            let mut stream = connect_tls(connector, &config.host, stream).await?;
            let _ = smtp_ehlo(&mut stream).await?;
            smtp_transaction(&mut stream, config, to, subject, body).await
        } else {
            smtp_transaction(&mut stream, config, to, subject, body).await
        }
    }
}

async fn connect_tls(
    connector: &TlsConnector,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| "SMTP TLS host name is invalid".to_owned())?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("establish SMTP TLS: {error}"))
}

async fn smtp_greeting<S>(stream: &mut S) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = read_response(stream).await?;
    ensure_code(&response, &[220], "SMTP greeting")
}

async fn smtp_ehlo<S>(stream: &mut S) -> Result<String, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_command(stream, "EHLO sub2api").await?;
    let response = read_response(stream).await?;
    if response.code == 250 {
        return Ok(response.message);
    }
    write_command(stream, "HELO sub2api").await?;
    let response = read_response(stream).await?;
    ensure_code(&response, &[250], "SMTP HELO")?;
    Ok(String::new())
}

async fn smtp_transaction<S>(
    stream: &mut S,
    config: &SmtpConfig,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    smtp_auth(stream, config).await?;
    expect_response(stream, &format!("MAIL FROM:<{}>", config.from), &[250]).await?;
    expect_response(stream, &format!("RCPT TO:<{to}>"), &[250, 251]).await?;
    expect_response(stream, "DATA", &[354]).await?;

    let from_header = if config.from_name.is_empty() {
        config.from.clone()
    } else {
        format!("{} <{}>", config.from_name, config.from)
    };
    let message = format!(
        "From: {from_header}\r\nTo: {to}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{body}",
        strip_header_controls(subject)
    );
    let mut data = dot_stuff(&message);
    if !data.ends_with("\r\n") {
        data.push_str("\r\n");
    }
    data.push_str(".\r\n");
    stream
        .write_all(data.as_bytes())
        .await
        .map_err(|error| format!("write SMTP message: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush SMTP message: {error}"))?;
    let response = read_response(stream).await?;
    ensure_code(&response, &[250], "SMTP message delivery")?;
    let _ = expect_response(stream, "QUIT", &[221]).await;
    Ok(())
}

async fn smtp_auth_and_quit<S>(stream: &mut S, config: &SmtpConfig) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    smtp_auth(stream, config).await?;
    expect_response(stream, "QUIT", &[221]).await
}

async fn smtp_auth<S>(stream: &mut S, config: &SmtpConfig) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if config.username.is_empty() && config.password.is_empty() {
        return Ok(());
    }
    let credentials = format!("\0{}\0{}", config.username, config.password);
    let command = format!("AUTH PLAIN {}", STANDARD.encode(credentials));
    expect_response(stream, &command, &[235, 503]).await
}

async fn expect_response<S>(stream: &mut S, command: &str, codes: &[u16]) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_command(stream, command).await?;
    let response = read_response(stream).await?;
    ensure_code(&response, codes, command)
}

async fn write_command<S>(stream: &mut S, command: &str) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    if contains_newline(command) {
        return Err("SMTP command contains invalid characters".to_owned());
    }
    stream
        .write_all(format!("{command}\r\n").as_bytes())
        .await
        .map_err(|error| format!("write SMTP command: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush SMTP command: {error}"))
}

struct SmtpResponse {
    code: u16,
    message: String,
}

async fn read_response<S>(stream: &mut S) -> Result<SmtpResponse, String>
where
    S: AsyncRead + Unpin,
{
    let mut message = String::new();
    let mut expected_code = None;
    loop {
        let mut raw = Vec::new();
        loop {
            let byte = stream
                .read_u8()
                .await
                .map_err(|error| format!("read SMTP response: {error}"))?;
            raw.push(byte);
            if byte == b'\n' {
                break;
            }
            if message.len() + raw.len() > MAX_SMTP_RESPONSE_BYTES {
                return Err("SMTP response is too large".to_owned());
            }
        }
        let line = std::str::from_utf8(&raw)
            .map_err(|_| "SMTP response is not valid UTF-8".to_owned())?
            .trim_end_matches(['\r', '\n']);
        if line.len() < 3 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err("SMTP server returned a malformed response".to_owned());
        }
        let code = line[..3]
            .parse::<u16>()
            .map_err(|_| "SMTP response code is invalid".to_owned())?;
        if expected_code
            .replace(code)
            .is_some_and(|expected| expected != code)
        {
            return Err("SMTP multiline response changed status code".to_owned());
        }
        if !message.is_empty() {
            message.push('\n');
        }
        message.push_str(line.get(4..).unwrap_or_default());
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok(SmtpResponse { code, message });
        }
    }
}

fn ensure_code(response: &SmtpResponse, expected: &[u16], operation: &str) -> Result<(), String> {
    if expected.contains(&response.code) {
        Ok(())
    } else {
        Err(format!(
            "{operation} failed with SMTP {}: {}",
            response.code, response.message
        ))
    }
}

fn valid_mailbox(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 320
        && !contains_newline(value)
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'<' | b'>'))
        })
}

fn contains_newline(value: &str) -> bool {
    value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
}

fn strip_header_controls(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n') && !character.is_control())
        .collect()
}

fn dot_stuff(message: &str) -> String {
    message
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        net::TcpListener,
    };

    use super::*;

    #[test]
    fn settings_require_a_valid_sender() {
        let mut values = HashMap::from([
            ("smtp_host".to_owned(), "smtp.example.com".to_owned()),
            ("smtp_username".to_owned(), "sender@example.com".to_owned()),
        ]);
        let config = SmtpConfig::from_settings(&values).unwrap();
        assert_eq!(config.port, 587);
        assert_eq!(config.from, "sender@example.com");

        values.insert("smtp_from".to_owned(), "bad\r\nBcc:x@y.z".to_owned());
        assert!(SmtpConfig::from_settings(&values).is_err());
    }

    #[test]
    fn smtp_data_is_normalized_and_dot_stuffed() {
        assert_eq!(
            dot_stuff("one\n.two\r\n..three"),
            "one\r\n..two\r\n...three"
        );
    }

    #[test]
    fn html_and_headers_are_sanitized() {
        assert_eq!(escape_html("<a&\"'>"), "&lt;a&amp;&quot;&#39;&gt;");
        assert_eq!(strip_header_controls("Sub2\r\nAPI"), "Sub2API");
    }

    #[tokio::test]
    async fn plain_smtp_delivery_completes_the_protocol() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            writer.write_all(b"220 localhost ESMTP\r\n").await.unwrap();
            let mut transcript = Vec::new();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let line = line.trim_end_matches(['\r', '\n']).to_owned();
                transcript.push(line.clone());
                if in_data {
                    if line == "." {
                        in_data = false;
                        writer.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let response = if line.starts_with("EHLO ") {
                    "250-localhost\r\n250 SIZE 1048576\r\n"
                } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                    "250 ok\r\n"
                } else if line == "DATA" {
                    in_data = true;
                    "354 send data\r\n"
                } else if line == "QUIT" {
                    writer.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    "500 unexpected\r\n"
                };
                writer.write_all(response.as_bytes()).await.unwrap();
            }
            transcript
        });

        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let notifier = PostgresSmtpNotifier::new(pool).unwrap();
        let config = SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port,
            username: String::new(),
            password: String::new(),
            from: "sender@example.com".to_owned(),
            from_name: "Sub2API".to_owned(),
            use_tls: false,
            site_name: "Sub2API".to_owned(),
            site_url: "https://example.com".to_owned(),
        };
        send_smtp(
            &notifier.tls,
            &config,
            "user@example.com",
            "Protocol test",
            ".leading line",
        )
        .await
        .unwrap();
        let transcript = server.await.unwrap();
        assert!(transcript.iter().any(|line| line == "..leading line"));
        assert!(transcript.iter().any(|line| line == "QUIT"));
    }
}
