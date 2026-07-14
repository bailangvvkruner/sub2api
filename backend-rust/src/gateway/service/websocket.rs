use std::{
    collections::HashSet,
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    http::{HeaderMap, Method, Uri},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        Message as UpstreamMessage, client::IntoClientRequest,
        handshake::client::Request as UpstreamRequest,
    },
};

use super::{
    AccountProxyRecord, AccountRecord, AccountSelection, ApiKeyLease, AuthContext, AuthorityLease,
    BillingContext, BillingObserver, BillingPricingOverride, BillingReservation,
    ChannelPolicyRecord, Decimal, GatewayError, GatewayErrorKind, GatewayLeases, GatewayRoute,
    GatewayRuntime, ModelMappingDecision, ModerationOutcome, Protocol, RequestMetadata,
    RequestType, ResponseMode, RouteKind, UsageProvider, UserLease, apply_channel_model_mapping,
    auth_gateway_error, billing_source, channel_billing_override, channel_model_restricted_error,
    classify_route, elapsed_millis, find_channel_pricing, gateway_error_response, mapped_model,
    parse_decimal_field, request_fingerprint, restriction_model, validate_upstream_adapter,
};

const FIRST_MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
const OPENAI_WEBSOCKET_BETA: &str = "responses_websockets=2026-02-06";
const PROXY_RESPONSE_LIMIT: usize = 16 * 1024;

trait WebSocketIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> WebSocketIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

type BoxedWebSocketIo = Box<dyn WebSocketIo>;
type UpstreamWebSocket = WebSocketStream<MaybeTlsStream<BoxedWebSocketIo>>;

struct TurnBilling {
    context: Option<BillingContext>,
    reservation: Option<BillingReservation>,
    started_at: Instant,
}

#[derive(Clone)]
struct WebSocketAccountContext {
    account: AccountRecord,
    channel_policy: Option<ChannelPolicyRecord>,
}

struct WebSocketModelPlan {
    upstream: String,
    billing: String,
    mapping_chain: Option<String>,
    pricing_override: Option<BillingPricingOverride>,
}

impl GatewayRuntime {
    /// Authenticates and upgrades an `OpenAI` Responses WebSocket request.
    #[allow(clippy::too_many_lines)]
    pub async fn responses_websocket(
        &self,
        upgrade: WebSocketUpgrade,
        uri: Uri,
        headers: HeaderMap,
        client_ip: Option<String>,
    ) -> Response {
        let post_uri = uri.clone();
        let Some(route) = classify_route(&Method::POST, &post_uri) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"error": {"message": "route not found"}})),
            )
                .into_response();
        };
        let auth = match self
            .authenticate(
                &headers,
                uri.query(),
                client_ip.as_deref(),
                self.inner.config.billing_enforced,
            )
            .await
        {
            Ok(auth) => auth,
            Err(error) => return gateway_error_response(&route, &auth_gateway_error(&error)),
        };
        let admission_id = uuid::Uuid::new_v4().to_string();
        let stable_billing_id = super::billing_request_id(&headers, &HeaderMap::new());
        if self.inner.config.billing_enforced
            && let Err(error) = self.validate_pending_billing(&auth)
        {
            return gateway_error_response(&route, &error);
        }
        let platform = auth
            .group
            .as_ref()
            .map_or("openai", |group| group.platform.as_str());
        if !matches!(platform, "openai" | "grok") {
            return gateway_error_response(
                &route,
                &GatewayError::new(
                    GatewayErrorKind::NotFound,
                    "Responses WebSocket is only available for OpenAI-compatible groups",
                ),
            );
        }
        if self.inner.config.billing_enforced {
            if let Err(error) = super::validate_user_platform_quota(
                &auth,
                platform,
                &self.inner.pending_billing,
                super::now_unix_millis(),
            ) {
                return gateway_error_response(&route, &error);
            }
            if let Err(error) = self.check_rpm(&auth, super::now_unix_millis()) {
                return gateway_error_response(&route, &error);
            }
            if let Err(error) = self
                .inner
                .authority
                .acquire_rate_limits(&auth, &admission_id)
                .await
            {
                return gateway_error_response(&route, &super::authority_gateway_error(&error));
            }
        }
        let user_lease = match UserLease::try_acquire(
            auth.subject.user_id,
            auth.subject.concurrency,
            Arc::clone(&self.inner.user_in_flight),
        ) {
            Ok(lease) => lease,
            Err(error) => return gateway_error_response(&route, &error),
        };
        let global_user_lease = match self
            .inner
            .authority
            .acquire_user_lease(
                auth.subject.user_id,
                &admission_id,
                auth.subject.concurrency,
            )
            .await
        {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                return gateway_error_response(
                    &route,
                    &GatewayError::new(GatewayErrorKind::RateLimit, "too many concurrent requests"),
                );
            }
            Err(error) => {
                return gateway_error_response(&route, &super::authority_gateway_error(&error));
            }
        };

        let runtime = self.clone();
        upgrade
            .max_message_size(self.inner.config.max_buffered_response_bytes)
            .on_upgrade(move |socket| async move {
                Box::pin(runtime.proxy_responses_websocket(
                    socket,
                    uri,
                    headers,
                    client_ip,
                    auth,
                    user_lease,
                    global_user_lease,
                    admission_id,
                    stable_billing_id,
                ))
                .await;
            })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn proxy_responses_websocket(
        &self,
        mut client: WebSocket,
        uri: Uri,
        headers: HeaderMap,
        client_ip: Option<String>,
        initial_auth: AuthContext,
        user_lease: UserLease,
        global_user_lease: AuthorityLease,
        admission_id: String,
        stable_billing_id: String,
    ) {
        let first = match tokio::time::timeout(FIRST_MESSAGE_TIMEOUT, client.recv()).await {
            Ok(Some(Ok(message))) => message,
            Ok(Some(Err(error))) => {
                tracing::debug!(error = %error, "read first Responses WebSocket message");
                return;
            }
            Ok(None) | Err(_) => {
                send_ws_error_and_close(
                    &mut client,
                    1008,
                    "invalid_request_error",
                    "missing first response.create message",
                )
                .await;
                return;
            }
        };
        let first_bytes = match client_data(&first) {
            Ok(bytes) => bytes,
            Err(message) => {
                send_ws_error_and_close(&mut client, 1008, "invalid_request_error", message).await;
                return;
            }
        };
        let first_metadata = match response_create_metadata(&first_bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                send_ws_error_and_close(&mut client, 1008, "invalid_request_error", &error.message)
                    .await;
                return;
            }
        };
        let moderation_route = GatewayRoute {
            protocol: Protocol::OpenAi,
            kind: RouteKind::OpenAiResponses,
            method: Method::POST,
            upstream_path: "/v1/responses".to_owned(),
            model_from_path: None,
        };
        match self
            .enforce_content_moderation_gate(
                &initial_auth,
                &moderation_route,
                &first_metadata,
                &first_bytes,
            )
            .await
        {
            Ok(ModerationOutcome::Allow) => {}
            Ok(ModerationOutcome::Block { message, .. }) => {
                send_ws_error_and_close(&mut client, 1008, "content_policy_violation", &message)
                    .await;
                return;
            }
            Err(error) => {
                send_ws_error_and_close(&mut client, 1013, "server_error", &error.message).await;
                return;
            }
        }
        let Some(api_key_id) = initial_auth.api_key.as_ref().map(|api_key| api_key.id) else {
            send_ws_error_and_close(
                &mut client,
                1011,
                "server_error",
                "authenticated request has no API key context",
            )
            .await;
            return;
        };
        let platform = initial_auth
            .group
            .as_ref()
            .map_or("openai", |group| group.platform.as_str());
        let (selection, mut upstream, first_outbound) = match self
            .connect_responses_websocket_account(
                &initial_auth,
                platform,
                &first_metadata,
                &first_bytes,
                &headers,
                &admission_id,
            )
            .await
        {
            Ok(connected) => connected,
            Err(error) => {
                send_ws_error_and_close(
                    &mut client,
                    ws_close_code(error.kind),
                    ws_error_type(error.kind),
                    &error.message,
                )
                .await;
                return;
            }
        };
        let account_context = WebSocketAccountContext {
            account: selection.account.clone(),
            channel_policy: selection.channel_policy.clone(),
        };
        let (first_billing, first_reservation) = if self.inner.config.billing_enforced {
            let model_plan =
                match websocket_model_plan(&account_context, first_metadata.model.as_deref()) {
                    Ok(plan) => plan,
                    Err(error) => {
                        send_ws_error_and_close(
                            &mut client,
                            ws_close_code(error.kind),
                            ws_error_type(error.kind),
                            &error.message,
                        )
                        .await;
                        return;
                    }
                };
            let context = match prepare_websocket_billing(
                &self.inner.billing_observer,
                &initial_auth,
                &account_context,
                &model_plan,
                &first_bytes,
                &stable_billing_id,
            ) {
                Ok(context) => context,
                Err(error) => {
                    send_ws_error_and_close(&mut client, 1011, "server_error", &error.message)
                        .await;
                    return;
                }
            };
            let reservation = match self
                .inner
                .authority
                .begin_billing(
                    &initial_auth,
                    selection.account.id,
                    &context.platform,
                    &context.request_id,
                    &context.request_fingerprint,
                )
                .await
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    send_ws_error_and_close(&mut client, 1013, "server_error", &error.to_string())
                        .await;
                    return;
                }
            };
            (Some(context), Some(reservation))
        } else {
            (None, None)
        };
        let api_key_lease =
            ApiKeyLease::acquire(api_key_id, Arc::clone(&self.inner.api_key_in_flight));
        let leases = GatewayLeases {
            _account: selection.lease,
            _global_account: Some(selection.global_lease),
            _api_key: api_key_lease,
            _user: user_lease,
            _global_user: Some(global_user_lease),
        };
        if let Err(error) = upstream
            .send(UpstreamMessage::Text(
                String::from_utf8_lossy(&first_outbound).into_owned().into(),
            ))
            .await
        {
            tracing::warn!(error = %error, "send first OpenAI Responses WebSocket message");
            send_ws_error_and_close(
                &mut client,
                1013,
                "server_error",
                "upstream service is unavailable",
            )
            .await;
            return;
        }
        self.queue_touch(&initial_auth, &account_context.account);
        let mut turn = Some(TurnBilling {
            context: first_billing,
            reservation: first_reservation,
            started_at: Instant::now(),
        });
        let _leases = leases;

        loop {
            tokio::select! {
                client_message = client.recv() => {
                    let Some(client_message) = client_message else {
                        let _ = upstream.close(None).await;
                        return;
                    };
                    let client_message = match client_message {
                        Ok(message) => message,
                        Err(error) => {
                            tracing::debug!(error = %error, "read Responses WebSocket client message");
                            let _ = upstream.close(None).await;
                            return;
                        }
                    };
                    match client_message {
                        Message::Text(text) => {
                            let bytes = text.as_bytes();
                            let outbound = match self.prepare_websocket_client_payload(
                                &headers,
                                &uri,
                                client_ip.as_deref(),
                                &account_context,
                                &mut turn,
                                bytes,
                            ).await {
                                Ok(outbound) => outbound,
                                Err(error) => {
                                    send_ws_error_and_close(
                                        &mut client,
                                        ws_close_code(error.kind),
                                        ws_error_type(error.kind),
                                        &error.message,
                                    ).await;
                                    let _ = upstream.close(None).await;
                                    return;
                                }
                            };
                            if upstream.send(UpstreamMessage::Text(
                                String::from_utf8_lossy(&outbound).into_owned().into()
                            )).await.is_err() {
                                send_ws_error_and_close(
                                    &mut client,
                                    1013,
                                    "server_error",
                                    "upstream service is unavailable",
                                ).await;
                                return;
                            }
                        }
                        Message::Binary(bytes) => {
                            let outbound = match self.prepare_websocket_client_payload(
                                &headers,
                                &uri,
                                client_ip.as_deref(),
                                &account_context,
                                &mut turn,
                                &bytes,
                            ).await {
                                Ok(outbound) => outbound,
                                Err(error) => {
                                    send_ws_error_and_close(
                                        &mut client,
                                        ws_close_code(error.kind),
                                        ws_error_type(error.kind),
                                        &error.message,
                                    ).await;
                                    let _ = upstream.close(None).await;
                                    return;
                                }
                            };
                            if upstream.send(UpstreamMessage::Binary(outbound.into())).await.is_err() {
                                return;
                            }
                        }
                        Message::Ping(bytes) => {
                            if upstream.send(UpstreamMessage::Ping(bytes)).await.is_err() {
                                return;
                            }
                        }
                        Message::Pong(bytes) => {
                            if upstream.send(UpstreamMessage::Pong(bytes)).await.is_err() {
                                return;
                            }
                        }
                        Message::Close(_) => {
                            let _ = upstream.close(None).await;
                            return;
                        }
                    }
                }
                upstream_message = upstream.next() => {
                    let Some(upstream_message) = upstream_message else {
                        let _ = client.send(Message::Close(None)).await;
                        return;
                    };
                    let upstream_message = match upstream_message {
                        Ok(message) => message,
                        Err(error) => {
                            tracing::warn!(account_id = account_context.account.id, error = %error, "read OpenAI Responses WebSocket upstream");
                            send_ws_error_and_close(
                                &mut client,
                                1013,
                                "server_error",
                                "upstream service is unavailable",
                            ).await;
                            return;
                        }
                    };
                    match upstream_message {
                        UpstreamMessage::Text(text) => {
                            let bytes = text.as_bytes();
                            if let Err(error) = self.observe_websocket_event(bytes, &mut turn).await {
                                send_ws_error_and_close(
                                    &mut client,
                                    ws_close_code(error.kind),
                                    ws_error_type(error.kind),
                                    &error.message,
                                ).await;
                                let _ = upstream.close(None).await;
                                return;
                            }
                            if client.send(Message::Text(text.to_string().into())).await.is_err() {
                                let _ = upstream.close(None).await;
                                return;
                            }
                        }
                        UpstreamMessage::Binary(bytes) => {
                            if let Err(error) = self.observe_websocket_event(&bytes, &mut turn).await {
                                send_ws_error_and_close(
                                    &mut client,
                                    ws_close_code(error.kind),
                                    ws_error_type(error.kind),
                                    &error.message,
                                ).await;
                                let _ = upstream.close(None).await;
                                return;
                            }
                            if client.send(Message::Binary(bytes)).await.is_err() {
                                let _ = upstream.close(None).await;
                                return;
                            }
                        }
                        UpstreamMessage::Ping(bytes) => {
                            if client.send(Message::Ping(bytes)).await.is_err() {
                                return;
                            }
                        }
                        UpstreamMessage::Pong(bytes) => {
                            if client.send(Message::Pong(bytes)).await.is_err() {
                                return;
                            }
                        }
                        UpstreamMessage::Close(_) => {
                            let _ = client.send(Message::Close(None)).await;
                            return;
                        }
                        UpstreamMessage::Frame(_) => {}
                    }
                }
            }
        }
    }

    async fn connect_responses_websocket_account(
        &self,
        auth: &AuthContext,
        platform: &str,
        metadata: &RequestMetadata,
        first_body: &[u8],
        client_headers: &HeaderMap,
        admission_id: &str,
    ) -> Result<(AccountSelection, UpstreamWebSocket, Vec<u8>), GatewayError> {
        let mut excluded_accounts = HashSet::new();
        let mut last_failure = None;
        loop {
            let selection = match self
                .select_account(auth, platform, metadata, &excluded_accounts, admission_id)
                .await
            {
                Ok(selection) => selection,
                Err(error) => return Err(last_failure.unwrap_or(error)),
            };
            excluded_accounts.insert(selection.account.id);
            if let Err(error) = validate_upstream_adapter(
                &selection.account.platform,
                &selection.account.account_type,
            ) {
                last_failure = Some(GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    error.to_string(),
                ));
                continue;
            }
            let first_outbound = rewrite_websocket_model(
                first_body,
                selection.mapped_model.as_deref(),
                metadata.model.as_deref(),
            );
            let upstream_request = match self
                .build_responses_websocket_request(&selection.account, client_headers)
                .await
            {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(
                        account_id = selection.account.id,
                        error = %error,
                        "prepare OpenAI Responses WebSocket upstream"
                    );
                    last_failure = Some(GatewayError::new(
                        GatewayErrorKind::Unavailable,
                        "upstream account configuration is unavailable",
                    ));
                    continue;
                }
            };
            match connect_account_websocket(
                &selection.account,
                upstream_request,
                self.inner.config.connect_timeout,
            )
            .await
            {
                Ok(upstream) => return Ok((selection, upstream, first_outbound)),
                Err(error) => {
                    tracing::warn!(
                        account_id = selection.account.id,
                        error = %error,
                        "connect OpenAI Responses WebSocket; trying another account"
                    );
                    self.record_account_transport_failure(
                        selection.account.id,
                        "WebSocket upstream transport failed",
                    )
                    .await;
                    last_failure = Some(GatewayError::new(
                        GatewayErrorKind::Unavailable,
                        "upstream service is unavailable",
                    ));
                }
            }
        }
    }

    async fn build_responses_websocket_request(
        &self,
        account: &AccountRecord,
        client_headers: &HeaderMap,
    ) -> Result<UpstreamRequest, String> {
        let (base_url, credential) = self
            .resolve_upstream_credentials(account, Protocol::OpenAi)
            .await?;
        let route = GatewayRoute {
            protocol: Protocol::OpenAi,
            kind: RouteKind::OpenAiResponses,
            method: Method::GET,
            upstream_path: "/v1/responses".to_owned(),
            model_from_path: None,
        };
        let oauth_account = account.account_type.eq_ignore_ascii_case("oauth");
        let openai_oauth = oauth_account && account.platform.eq_ignore_ascii_case("openai");
        let grok_oauth = oauth_account && account.platform.eq_ignore_ascii_case("grok");
        let mut upstream_url = if openai_oauth {
            let configured = super::adapter_credential(&account.credentials, "base_url")
                .unwrap_or_else(|| super::super::adapters::OPENAI_CODEX_URL.to_owned());
            url::Url::parse(&configured).map_err(|_| "invalid upstream WebSocket URL".to_owned())?
        } else {
            crate::gateway::build_upstream_url(&base_url, &route, ResponseMode::Buffered)
                .map_err(|_| "invalid upstream WebSocket URL".to_owned())?
        };
        let websocket_scheme = if upstream_url.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        upstream_url
            .set_scheme(websocket_scheme)
            .map_err(|()| "invalid upstream WebSocket URL".to_owned())?;
        let mut request = upstream_url
            .as_str()
            .into_client_request()
            .map_err(|_| "invalid upstream WebSocket request".to_owned())?;
        let mut headers = crate::gateway::build_upstream_headers(
            Protocol::OpenAi,
            &Method::GET,
            ResponseMode::Buffered,
            &credential,
            client_headers,
        )
        .map_err(|_| "invalid upstream WebSocket headers".to_owned())?;
        if openai_oauth {
            headers.insert(
                "originator",
                "codex_cli_rs"
                    .parse()
                    .expect("static originator header is valid"),
            );
            headers.insert(
                axum::http::header::USER_AGENT,
                "codex_cli_rs/0.144.1 (Ubuntu 22.4.0; x86_64) xterm-256color"
                    .parse()
                    .expect("static User-Agent is valid"),
            );
            if let Some(account_id) =
                super::adapter_credential(&account.credentials, "chatgpt_account_id")
                && let Ok(account_id) = account_id.parse()
            {
                headers.insert("chatgpt-account-id", account_id);
            }
        } else if grok_oauth {
            headers.insert(
                axum::http::header::USER_AGENT,
                "sub2api-grok/1.0"
                    .parse()
                    .expect("static User-Agent is valid"),
            );
        }
        for (name, value) in headers {
            if let Some(name) = name {
                request.headers_mut().insert(name, value);
            }
        }
        request.headers_mut().insert(
            "openai-beta",
            OPENAI_WEBSOCKET_BETA
                .parse()
                .expect("static OpenAI beta header is valid"),
        );
        Ok(request)
    }

    async fn prepare_websocket_client_payload(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        client_ip: Option<&str>,
        account_context: &WebSocketAccountContext,
        turn: &mut Option<TurnBilling>,
        body: &[u8],
    ) -> Result<Vec<u8>, GatewayError> {
        if !is_response_create(body) {
            return Ok(body.to_vec());
        }
        if turn.is_some() {
            return Err(GatewayError::new(
                GatewayErrorKind::InvalidRequest,
                "a response is already in progress",
            ));
        }
        let (context, reservation, outbound) = self
            .prepare_subsequent_websocket_turn(headers, uri, client_ip, account_context, body)
            .await?;
        *turn = Some(TurnBilling {
            context,
            reservation,
            started_at: Instant::now(),
        });
        Ok(outbound)
    }

    async fn observe_websocket_event(
        &self,
        body: &[u8],
        turn: &mut Option<TurnBilling>,
    ) -> Result<(), GatewayError> {
        match websocket_event_type(body).as_deref() {
            Some("response.completed") => {
                let completed = turn.take().ok_or_else(|| {
                    GatewayError::new(
                        GatewayErrorKind::Internal,
                        "upstream completed an unknown response",
                    )
                })?;
                let Some(context) = completed.context else {
                    return Ok(());
                };
                let mut reservation = completed.reservation.ok_or_else(|| {
                    GatewayError::new(
                        GatewayErrorKind::Internal,
                        "durable WebSocket billing reservation is missing",
                    )
                })?;
                let event = self
                    .inner
                    .billing_observer
                    .observe_json(
                        UsageProvider::OpenAi,
                        context,
                        body,
                        Some(elapsed_millis(completed.started_at)),
                    )
                    .map_err(|error| {
                        tracing::error!(error = %error, "observe Responses WebSocket billing");
                        GatewayError::new(
                            GatewayErrorKind::Internal,
                            "failed to process upstream usage",
                        )
                    })?;
                reservation.stage(&event).await.map_err(|error| {
                    tracing::error!(error = %error, "stage durable Responses WebSocket billing");
                    GatewayError::new(
                        GatewayErrorKind::Unavailable,
                        "billing service is temporarily unavailable",
                    )
                })?;
                self.inner
                    .billing_writes
                    .enqueue(event)
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %error, "enqueue Responses WebSocket billing");
                        GatewayError::new(
                            GatewayErrorKind::Unavailable,
                            "billing service is temporarily unavailable",
                        )
                    })?;
            }
            Some("response.failed") => *turn = None,
            _ => {}
        }
        Ok(())
    }

    async fn prepare_subsequent_websocket_turn(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        client_ip: Option<&str>,
        account_context: &WebSocketAccountContext,
        body: &[u8],
    ) -> Result<(Option<BillingContext>, Option<BillingReservation>, Vec<u8>), GatewayError> {
        let auth = self
            .authenticate(
                headers,
                uri.query(),
                client_ip,
                self.inner.config.billing_enforced,
            )
            .await
            .map_err(|error| auth_gateway_error(&error))?;
        if self.inner.config.billing_enforced {
            self.validate_pending_billing(&auth)?;
            super::validate_user_platform_quota(
                &auth,
                &account_context.account.platform,
                &self.inner.pending_billing,
                super::now_unix_millis(),
            )?;
            self.check_rpm(&auth, super::now_unix_millis())?;
        }
        let admission_id = uuid::Uuid::new_v4().to_string();
        if self.inner.config.billing_enforced {
            self.inner
                .authority
                .acquire_rate_limits(&auth, &admission_id)
                .await
                .map_err(|error| super::authority_gateway_error(&error))?;
        }
        let metadata = response_create_metadata(body)?;
        let model_plan = websocket_model_plan(account_context, metadata.model.as_deref())?;
        let (context, reservation) = if self.inner.config.billing_enforced {
            let context = prepare_websocket_billing(
                &self.inner.billing_observer,
                &auth,
                account_context,
                &model_plan,
                body,
                &uuid::Uuid::new_v4().to_string(),
            )?;
            let reservation = self
                .inner
                .authority
                .begin_billing(
                    &auth,
                    account_context.account.id,
                    &context.platform,
                    &context.request_id,
                    &context.request_fingerprint,
                )
                .await
                .map_err(|error| super::authority_gateway_error(&error))?;
            (Some(context), Some(reservation))
        } else {
            (None, None)
        };
        let outbound =
            rewrite_websocket_model(body, Some(&model_plan.upstream), metadata.model.as_deref());
        Ok((context, reservation, outbound))
    }
}

async fn connect_account_websocket(
    account: &AccountRecord,
    request: UpstreamRequest,
    timeout: Duration,
) -> Result<UpstreamWebSocket, String> {
    let target = WebSocketTarget::from_request(&request)?;
    let proxy = match account.proxy_id {
        Some(_) => Some(
            account
                .proxy
                .as_ref()
                .ok_or_else(|| "configured account proxy is unavailable".to_owned())?,
        ),
        None => None,
    };
    let connect = async {
        let transport: BoxedWebSocketIo = match proxy {
            Some(proxy) => connect_proxy_tunnel(proxy, &target)
                .await
                .map_err(|_| "upstream proxy connection failed".to_owned())?,
            None => Box::new(
                TcpStream::connect((target.host.as_str(), target.port))
                    .await
                    .map_err(|_| "upstream connection failed".to_owned())?,
            ),
        };
        client_async_tls_with_config(request, transport, None, None)
            .await
            .map(|(socket, _)| socket)
            .map_err(|_| "upstream WebSocket handshake failed".to_owned())
    };
    tokio::time::timeout(timeout, connect)
        .await
        .map_err(|_| "upstream WebSocket connection timed out".to_owned())?
}

struct WebSocketTarget {
    host: String,
    port: u16,
}

impl WebSocketTarget {
    fn from_request(request: &UpstreamRequest) -> Result<Self, String> {
        let host = request
            .uri()
            .host()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "upstream WebSocket host is missing".to_owned())?;
        let port = request
            .uri()
            .port_u16()
            .or_else(|| match request.uri().scheme_str() {
                Some("wss") => Some(443),
                Some("ws") => Some(80),
                _ => None,
            });
        Ok(Self {
            host: host.trim_matches(['[', ']']).to_owned(),
            port: port.ok_or_else(|| "upstream WebSocket port is missing".to_owned())?,
        })
    }

    fn authority(&self) -> String {
        if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

async fn connect_proxy_tunnel(
    proxy: &AccountProxyRecord,
    target: &WebSocketTarget,
) -> io::Result<BoxedWebSocketIo> {
    let proxy_host = proxy.host.trim().trim_matches(['[', ']']);
    let proxy_port = u16::try_from(proxy.port)
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy port"))?;
    if proxy_host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid proxy host",
        ));
    }
    let tcp = TcpStream::connect((proxy_host, proxy_port)).await?;
    tcp.set_nodelay(true)?;
    let protocol = proxy.protocol.trim().to_ascii_lowercase();
    let mut stream: BoxedWebSocketIo = match protocol.as_str() {
        "https" => Box::new(connect_tls_proxy(tcp, proxy_host).await?),
        "http" | "socks5" | "socks5h" => Box::new(tcp),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported proxy protocol",
            ));
        }
    };
    match protocol.as_str() {
        "http" | "https" => http_connect_tunnel(&mut stream, proxy, target).await?,
        "socks5" => socks5_connect_tunnel(&mut stream, proxy, target, false).await?,
        "socks5h" => socks5_connect_tunnel(&mut stream, proxy, target, true).await?,
        _ => unreachable!("proxy protocol was validated above"),
    }
    Ok(stream)
}

async fn connect_tls_proxy(
    tcp: TcpStream,
    proxy_host: &str,
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(proxy_host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTPS proxy host"))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
}

async fn http_connect_tunnel(
    stream: &mut BoxedWebSocketIo,
    proxy: &AccountProxyRecord,
    target: &WebSocketTarget,
) -> io::Result<()> {
    let authority = target.authority();
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(username) = proxy
        .username
        .as_deref()
        .map(str::trim)
        .filter(|username| !username.is_empty())
    {
        let password = proxy.password.as_deref().unwrap_or_default();
        let credentials = BASE64_STANDARD.encode(format!("{username}:{password}"));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&credentials);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::with_capacity(512);
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= PROXY_RESPONSE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy response headers exceed limit",
            ));
        }
        let byte = stream.read_u8().await?;
        response.push(byte);
    }
    let first_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    let status = first_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok());
    if status != Some(200) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy CONNECT request was rejected",
        ));
    }
    Ok(())
}

async fn socks5_connect_tunnel(
    stream: &mut BoxedWebSocketIo,
    proxy: &AccountProxyRecord,
    target: &WebSocketTarget,
    remote_dns: bool,
) -> io::Result<()> {
    let username = proxy
        .username
        .as_deref()
        .map(str::trim)
        .filter(|username| !username.is_empty());
    let methods: &[u8] = if username.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(methods).await?;
    stream.flush().await?;
    let mut method = [0_u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 0x05 || method[1] == 0xff {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy rejected authentication methods",
        ));
    }
    match method[1] {
        0x00 => {}
        0x02 => authenticate_socks5(stream, username, proxy.password.as_deref()).await?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy selected an unsupported authentication method",
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    if remote_dns {
        append_socks5_domain(&mut request, &target.host)?;
    } else if let Ok(ip) = target.host.parse::<IpAddr>() {
        append_socks5_ip(&mut request, ip);
    } else {
        let mut addresses = tokio::net::lookup_host((target.host.as_str(), target.port)).await?;
        let address = addresses.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "upstream DNS returned no addresses",
            )
        })?;
        append_socks5_ip(&mut request, address.ip());
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut response = [0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS5 proxy could not connect to upstream",
        ));
    }
    match response[3] {
        0x01 => discard_exact(stream, 4).await?,
        0x03 => {
            let length = usize::from(stream.read_u8().await?);
            discard_exact(stream, length).await?;
        }
        0x04 => discard_exact(stream, 16).await?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 proxy returned an invalid address type",
            ));
        }
    }
    discard_exact(stream, 2).await
}

async fn authenticate_socks5(
    stream: &mut BoxedWebSocketIo,
    username: Option<&str>,
    password: Option<&str>,
) -> io::Result<()> {
    let username = username.unwrap_or_default().as_bytes();
    let password = password.unwrap_or_default().as_bytes();
    let username_len = u8::try_from(username.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "proxy username is too long"))?;
    let password_len = u8::try_from(password.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "proxy password is too long"))?;
    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.extend_from_slice(&[0x01, username_len]);
    request.extend_from_slice(username);
    request.push(password_len);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = [0_u8; 2];
    stream.read_exact(&mut response).await?;
    if response != [0x01, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy authentication failed",
        ));
    }
    Ok(())
}

fn append_socks5_domain(request: &mut Vec<u8>, host: &str) -> io::Result<()> {
    let bytes = host.as_bytes();
    let length = u8::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "upstream host is too long"))?;
    request.extend_from_slice(&[0x03, length]);
    request.extend_from_slice(bytes);
    Ok(())
}

fn append_socks5_ip(request: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
}

async fn discard_exact(stream: &mut BoxedWebSocketIo, length: usize) -> io::Result<()> {
    let mut remaining = length;
    let mut buffer = [0_u8; 32];
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..count]).await?;
        remaining -= count;
    }
    Ok(())
}

fn websocket_model_plan(
    account_context: &WebSocketAccountContext,
    requested: Option<&str>,
) -> Result<WebSocketModelPlan, GatewayError> {
    let requested = requested
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| GatewayError::new(GatewayErrorKind::InvalidRequest, "model is required"))?;
    let policy = account_context.channel_policy.as_ref();
    let channel_mapped = apply_channel_model_mapping(policy, Some(requested))
        .filter(|model| !model.trim().is_empty())
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorKind::Internal,
                "invalid channel model mapping configuration",
            )
        })?;
    if let Some(policy) = policy
        && policy.restrict_models
        && !billing_source(policy).eq_ignore_ascii_case("upstream")
        && restriction_model(policy, Some(requested), Some(&channel_mapped), None)
            .is_some_and(|model| find_channel_pricing(policy, model).is_none())
    {
        return Err(channel_model_restricted_error());
    }
    let upstream = match mapped_model(&account_context.account, Some(&channel_mapped)) {
        ModelMappingDecision::Allowed(Some(model)) => model,
        ModelMappingDecision::Allowed(None) | ModelMappingDecision::Unsupported => {
            return Err(GatewayError::new(
                GatewayErrorKind::NotFound,
                "model is not available on the selected account",
            ));
        }
    };
    if let Some(policy) = policy
        && policy.restrict_models
        && billing_source(policy).eq_ignore_ascii_case("upstream")
        && find_channel_pricing(policy, &upstream).is_none()
    {
        return Err(channel_model_restricted_error());
    }
    let billing = policy
        .map_or(upstream.as_str(), |policy| {
            restriction_model(
                policy,
                Some(requested),
                Some(&channel_mapped),
                Some(&upstream),
            )
            .unwrap_or(&upstream)
        })
        .to_owned();
    let pricing_override = policy
        .map(|policy| channel_billing_override(policy, &billing))
        .transpose()?
        .flatten();
    let mut chain = vec![requested];
    if !channel_mapped.eq_ignore_ascii_case(chain.last().copied().unwrap_or_default()) {
        chain.push(&channel_mapped);
    }
    if !upstream.eq_ignore_ascii_case(chain.last().copied().unwrap_or_default()) {
        chain.push(&upstream);
    }
    let mapping_chain = (chain.len() > 1).then(|| chain.join("->"));
    Ok(WebSocketModelPlan {
        upstream,
        billing,
        mapping_chain,
        pricing_override,
    })
}

fn prepare_websocket_billing(
    observer: &BillingObserver,
    auth: &AuthContext,
    account_context: &WebSocketAccountContext,
    model_plan: &WebSocketModelPlan,
    body: &[u8],
    request_id: &str,
) -> Result<BillingContext, GatewayError> {
    let api_key = auth.api_key.as_ref().ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::Internal,
            "authenticated request has no API key billing context",
        )
    })?;
    observer
        .preflight_model_with_override(
            &model_plan.billing,
            model_plan.pricing_override.as_ref(),
        )
        .map_err(|error| {
            tracing::error!(model = %model_plan.billing, error = %error, "preflight Responses WebSocket billing");
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "billing is unavailable for the selected model",
            )
        })?;
    let group_multiplier = auth.group.as_ref().map_or(Ok(Decimal::ONE), |group| {
        parse_decimal_field(&group.rate_multiplier, "group billing multiplier")
    })?;
    let account_multiplier = parse_decimal_field(
        &account_context.account.rate_multiplier,
        "account billing multiplier",
    )?;
    if group_multiplier.is_negative() || account_multiplier.is_negative() {
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid billing multiplier configuration",
        ));
    }
    Ok(BillingContext {
        request_id: request_id.to_owned(),
        request_fingerprint: request_fingerprint(body),
        user_id: auth.user.id,
        api_key_id: api_key.id,
        account_id: account_context.account.id,
        group_id: api_key.group_id,
        channel_id: account_context
            .channel_policy
            .as_ref()
            .map(|policy| policy.id),
        platform: account_context.account.platform.to_ascii_lowercase(),
        model: model_plan.billing.clone(),
        model_mapping_chain: model_plan.mapping_chain.clone(),
        pricing_override: model_plan.pricing_override.clone(),
        group_multiplier,
        account_multiplier,
        stream: false,
        request_type: RequestType::OpenAiWebSocket,
    })
}

fn response_create_metadata(body: &[u8]) -> Result<RequestMetadata, GatewayError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        GatewayError::new(
            GatewayErrorKind::InvalidRequest,
            "invalid JSON response.create payload",
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::InvalidRequest,
            "response.create payload must be a JSON object",
        )
    })?;
    if object.get("type").and_then(Value::as_str) != Some("response.create") {
        return Err(GatewayError::new(
            GatewayErrorKind::InvalidRequest,
            "first WebSocket message must be response.create",
        ));
    }
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorKind::InvalidRequest,
                "model is required in response.create payload",
            )
        })?;
    Ok(RequestMetadata {
        model: Some(model.to_owned()),
        stream: true,
    })
}

fn is_response_create(body: &[u8]) -> bool {
    websocket_event_type(body).as_deref() == Some("response.create")
}

fn websocket_event_type(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value.get("type")?.as_str().map(str::to_owned)
}

fn rewrite_websocket_model(body: &[u8], mapped: Option<&str>, requested: Option<&str>) -> Vec<u8> {
    let Some(mapped) = mapped else {
        return body.to_vec();
    };
    if requested == Some(mapped) {
        return body.to_vec();
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("model".to_owned(), Value::String(mapped.to_owned()));
    }
    serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec())
}

fn client_data(message: &Message) -> Result<Vec<u8>, &'static str> {
    match message {
        Message::Text(text) => Ok(text.as_bytes().to_vec()),
        Message::Binary(bytes) => Ok(bytes.to_vec()),
        _ => Err("unsupported first WebSocket message type"),
    }
}

async fn send_ws_error_and_close(
    socket: &mut WebSocket,
    close_code: u16,
    error_type: &str,
    message: &str,
) {
    let payload = websocket_error_payload(error_type, message);
    let _ = socket.send(Message::Text(payload.into())).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: close_code,
            reason: "request_failed".into(),
        })))
        .await;
}

fn websocket_error_payload(error_type: &str, message: &str) -> String {
    json!({
        "type": "error",
        "error": {
            "type": error_type,
            "code": error_type,
            "message": message,
        }
    })
    .to_string()
}

const fn ws_close_code(kind: GatewayErrorKind) -> u16 {
    match kind {
        GatewayErrorKind::InvalidRequest | GatewayErrorKind::Permission => 1008,
        GatewayErrorKind::RateLimit | GatewayErrorKind::Unavailable => 1013,
        _ => 1011,
    }
}

const fn ws_error_type(kind: GatewayErrorKind) -> &'static str {
    match kind {
        GatewayErrorKind::InvalidRequest => "invalid_request_error",
        GatewayErrorKind::Permission => "permission_error",
        GatewayErrorKind::RateLimit => "rate_limit_error",
        _ => "server_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(protocol: &str) -> AccountProxyRecord {
        AccountProxyRecord {
            id: 1,
            protocol: protocol.to_owned(),
            host: "proxy.internal".to_owned(),
            port: 1080,
            username: Some("proxy-user".to_owned()),
            password: Some("proxy-secret".to_owned()),
            status: "active".to_owned(),
            expires_at_unix_ms: None,
        }
    }

    #[test]
    fn first_frame_requires_response_create_and_model() {
        assert!(response_create_metadata(br#"{"type":"response.create","model":"gpt-5"}"#).is_ok());
        assert!(
            response_create_metadata(br#"{"type":"response.cancel","model":"gpt-5"}"#).is_err()
        );
        assert!(response_create_metadata(br#"{"type":"response.create"}"#).is_err());
    }

    #[test]
    fn model_rewrite_preserves_other_fields() {
        let rewritten = rewrite_websocket_model(
            br#"{"type":"response.create","model":"public-model","input":"hello"}"#,
            Some("upstream-model"),
            Some("public-model"),
        );
        let value: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["model"], "upstream-model");
        assert_eq!(value["input"], "hello");
    }

    #[test]
    fn terminal_protocol_error_has_openai_shape() {
        let value: Value = serde_json::from_str(&websocket_error_payload(
            "server_error",
            "billing unavailable",
        ))
        .unwrap();
        assert_eq!(value["type"], "error");
        assert_eq!(value["error"]["type"], "server_error");
    }

    #[tokio::test]
    async fn http_connect_tunnels_with_basic_proxy_auth() {
        let (client, mut server) = tokio::io::duplex(4_096);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(server.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT api.openai.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic "));
            assert!(!request.contains("proxy-secret"));
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream: BoxedWebSocketIo = Box::new(client);
        http_connect_tunnel(
            &mut stream,
            &proxy("http"),
            &WebSocketTarget {
                host: "api.openai.com".to_owned(),
                port: 443,
            },
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5h_keeps_upstream_dns_on_the_proxy() {
        let (client, mut server) = tokio::io::duplex(4_096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0_u8; 4];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            server.write_all(&[0x05, 0x00]).await.unwrap();

            let mut header = [0_u8; 4];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(header, [0x05, 0x01, 0x00, 0x03]);
            let length = usize::from(server.read_u8().await.unwrap());
            let mut host = vec![0_u8; length];
            server.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"api.openai.com");
            let mut port = [0_u8; 2];
            server.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
                .await
                .unwrap();
        });
        let mut stream: BoxedWebSocketIo = Box::new(client);
        let configured_proxy = proxy("socks5h");
        socks5_connect_tunnel(
            &mut stream,
            &configured_proxy,
            &WebSocketTarget {
                host: "api.openai.com".to_owned(),
                port: 443,
            },
            true,
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }
}
