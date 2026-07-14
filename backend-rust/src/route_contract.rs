use axum::http::Method;

const GO_ROUTES_TSV: &str = include_str!("../docs/go-routes.tsv");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteContract<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub handler: &'a str,
    pub auth: &'a str,
    pub source: &'a str,
    pub category: &'a str,
    pub dynamic: bool,
    pub transport: &'a str,
}

impl RouteContract<'_> {
    #[must_use]
    pub fn matches(&self, method: &Method, path: &str) -> bool {
        self.method == method.as_str() && path_matches(self.path, path)
    }

    #[must_use]
    pub fn representative_path(&self) -> String {
        representative_path(self.path)
    }
}

pub fn routes() -> impl Iterator<Item = RouteContract<'static>> {
    GO_ROUTES_TSV.lines().skip(1).filter_map(parse_route)
}

#[must_use]
pub fn find(method: &Method, path: &str) -> Option<RouteContract<'static>> {
    routes().find(|route| route.matches(method, path))
}

fn parse_route(line: &'static str) -> Option<RouteContract<'static>> {
    let mut fields = line.split('\t');
    let route = RouteContract {
        method: fields.next()?,
        path: fields.next()?,
        handler: fields.next()?,
        auth: fields.next()?,
        source: fields.next()?,
        category: fields.next()?,
        dynamic: fields.next()? == "yes",
        transport: fields.next()?,
    };
    fields.next().is_none().then_some(route)
}

fn path_matches(pattern: &str, candidate: &str) -> bool {
    let pattern = path_segments(pattern);
    let candidate = path_segments(candidate);
    let mut candidate_index = 0;
    for segment in pattern {
        if segment.starts_with('*') {
            return true;
        }
        let Some(value) = candidate.get(candidate_index) else {
            return false;
        };
        if !segment.starts_with(':') && segment != *value {
            return false;
        }
        candidate_index += 1;
    }
    candidate_index == candidate.len()
}

fn representative_path(pattern: &str) -> String {
    if pattern == "/" {
        return "/".to_owned();
    }
    let segments = path_segments(pattern)
        .into_iter()
        .map(|segment| {
            if segment.starts_with(':') {
                representative_parameter(segment)
            } else if segment.starts_with('*') {
                representative_wildcard(segment)
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn representative_wildcard(parameter: &str) -> &'static str {
    if parameter.contains("modelAction") {
        "gemini-2.5-pro:generateContent"
    } else {
        "nested/value"
    }
}

fn representative_parameter(parameter: &str) -> &'static str {
    if parameter.contains("slug") {
        "example"
    } else if parameter.contains("provider") {
        "github"
    } else if parameter.contains("request_id") || parameter.contains("custom_id") {
        "request-1"
    } else if parameter.contains("model") {
        "model-1"
    } else {
        "1"
    }
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn embedded_inventory_has_the_production_census() {
        let routes = routes().collect::<Vec<_>>();
        assert_eq!(routes.len(), 532);
        assert_eq!(
            routes
                .iter()
                .map(|route| (route.method, route.path))
                .collect::<HashSet<_>>()
                .len(),
            531
        );
        assert_eq!(routes.iter().filter(|route| route.dynamic).count(), 178);
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.transport.contains("websocket"))
                .count(),
            4
        );
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.transport.contains("sse"))
                .count(),
            12
        );
    }

    #[test]
    fn representative_dynamic_paths_match_their_contract() {
        for route in routes() {
            let method = Method::from_bytes(route.method.as_bytes()).unwrap();
            let path = route.representative_path();
            assert!(route.matches(&method, &path), "{method} {path}");
        }
    }

    #[test]
    fn matcher_rejects_static_and_method_mismatches() {
        let method = Method::GET;
        assert!(find(&method, "/api/v1/pages/example/images/nested/file.png").is_some());
        assert!(find(&Method::POST, "/health").is_none());
        assert!(find(&method, "/api/v1/not-a-real-route").is_none());
    }

    #[test]
    fn representative_gemini_wildcard_is_a_valid_model_action() {
        assert_eq!(
            representative_path("/v1beta/models/*modelAction"),
            "/v1beta/models/gemini-2.5-pro:generateContent"
        );
    }
}
