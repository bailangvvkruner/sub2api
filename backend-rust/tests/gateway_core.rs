use axum::http::{Method, Uri};
use sub2api_rust::gateway::{Protocol, RouteKind, classify_route};

#[test]
fn public_gateway_contract_is_wired_into_the_library() {
    let uri: Uri = "/v1/messages".parse().expect("gateway URI should parse");
    let route = classify_route(&Method::POST, &uri).expect("gateway route should be registered");

    assert_eq!(route.protocol, Protocol::Anthropic);
    assert_eq!(route.kind, RouteKind::AnthropicMessages);
}
