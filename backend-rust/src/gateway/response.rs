use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};

/// Framing used to relay the upstream response body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseMode {
    Buffered,
    ServerSentEvents,
}

/// An opaque buffered body or byte stream owned by the HTTP adapter.
#[derive(Debug)]
pub enum PassthroughBody<Stream> {
    Buffered(Vec<u8>),
    Stream(Stream),
}

impl<Stream> PassthroughBody<Stream> {
    /// Transforms the opaque stream while leaving a buffered body untouched.
    #[must_use]
    pub fn map_stream<Mapped>(self, map: impl FnOnce(Stream) -> Mapped) -> PassthroughBody<Mapped> {
        match self {
            Self::Buffered(body) => PassthroughBody::Buffered(body),
            Self::Stream(stream) => PassthroughBody::Stream(map(stream)),
        }
    }

    /// Returns the response framing represented by this body.
    #[must_use]
    pub const fn mode(&self) -> ResponseMode {
        match self {
            Self::Buffered(_) => ResponseMode::Buffered,
            Self::Stream(_) => ResponseMode::ServerSentEvents,
        }
    }
}

/// Status, headers, and body returned by an upstream HTTP adapter.
#[derive(Debug)]
pub struct UpstreamResponse<Stream> {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: PassthroughBody<Stream>,
}

/// Sanitized response parts ready to convert into an Axum response.
#[derive(Debug)]
pub struct ClientResponsePlan<Stream> {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: PassthroughBody<Stream>,
}

/// Resolves framing from the request and upstream `Content-Type`.
///
/// An upstream SSE content type wins even when a compatibility endpoint
/// unexpectedly streams after receiving `stream: false`.
#[must_use]
pub fn response_mode_from_headers(requested: ResponseMode, headers: &HeaderMap) -> ResponseMode {
    if requested == ResponseMode::ServerSentEvents
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
            })
    {
        ResponseMode::ServerSentEvents
    } else {
        ResponseMode::Buffered
    }
}

/// Removes hop-by-hop and upstream infrastructure headers while preserving
/// the body as an opaque value. Streaming responses also disable proxy
/// buffering and content-length forwarding.
#[must_use]
pub fn prepare_passthrough<Stream>(
    upstream: UpstreamResponse<Stream>,
) -> ClientResponsePlan<Stream> {
    let mode = upstream.body.mode();
    let mut headers = HeaderMap::new();
    for (name, value) in &upstream.headers {
        if response_header_allowed(name, mode) {
            headers.append(name, value.clone());
        }
    }

    if mode == ResponseMode::ServerSentEvents {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-cache"));
        headers.insert(
            HeaderName::from_static("x-accel-buffering"),
            HeaderValue::from_static("no"),
        );
    }

    ClientResponsePlan {
        status: upstream.status,
        headers,
        body: upstream.body,
    }
}

fn response_header_allowed(name: &HeaderName, mode: ResponseMode) -> bool {
    if mode == ResponseMode::ServerSentEvents && name == header::CONTENT_LENGTH {
        return false;
    }
    !matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "server"
            | "set-cookie"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "via"
    )
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

    use super::{PassthroughBody, ResponseMode, UpstreamResponse, prepare_passthrough};

    #[test]
    fn streaming_response_stays_opaque_and_drops_transport_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("123"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("x-request-id", HeaderValue::from_static("req_123"));
        let upstream = UpstreamResponse {
            status: StatusCode::OK,
            headers,
            body: PassthroughBody::Stream("opaque-stream"),
        };

        let client = prepare_passthrough(upstream);

        assert_eq!(client.body.mode(), ResponseMode::ServerSentEvents);
        assert_eq!(client.headers[header::CONTENT_TYPE], "text/event-stream");
        assert_eq!(client.headers["x-request-id"], "req_123");
        assert!(!client.headers.contains_key(header::CONTENT_LENGTH));
        assert!(!client.headers.contains_key(header::CONNECTION));
    }

    #[test]
    fn buffered_response_keeps_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("2"));
        let upstream: UpstreamResponse<()> = UpstreamResponse {
            status: StatusCode::OK,
            headers,
            body: PassthroughBody::Buffered(b"{}".to_vec()),
        };

        let client = prepare_passthrough(upstream);
        assert_eq!(client.headers[header::CONTENT_LENGTH], "2");
    }
}
