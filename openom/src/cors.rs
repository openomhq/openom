//! CORS: let the deployment's configured browser origins (`OPENOM_WEB_ORIGINS`) call the API
//! cross-origin. Exact origins and single-label wildcard patterns (e.g. Cloudflare Pages previews)
//! are matched against the request's `Origin`; anything else gets no CORS headers, so the browser
//! blocks it. This is the same allow-list the R2 bucket CORS and the Pages CSP `connect-src` use.

use axum::http::{HeaderName, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Build the CORS layer for the configured origins, or `None` when none are set — in which case no
/// CORS layer is added at all (no `Access-Control-Allow-Origin` headers → same-origin only).
pub(crate) fn layer(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let patterns = origins.to_vec();
    let allow = AllowOrigin::predicate(move |origin, _parts| {
        origin
            .to_str()
            .is_ok_and(|o| patterns.iter().any(|p| origin_matches(o, p)))
    });
    Some(
        CorsLayer::new()
            .allow_origin(allow)
            // Token-in-header auth (Bearer, in `Authorization` or `Openom-Auth`), so no credential/cookie mode.
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                HeaderName::from_static("authorization"),
                // The JWT header used when behind CloudFront OAC (which claims `Authorization`).
                HeaderName::from_static("openom-auth"),
                // SHA-256 of the request body, required by a Function URL origin under OAC/AWS_IAM.
                HeaderName::from_static("x-amz-content-sha256"),
                HeaderName::from_static("content-type"),
                HeaderName::from_static("if-match"),
                HeaderName::from_static("if-none-match"),
                HeaderName::from_static("traceparent"),
                HeaderName::from_static("x-request-id"),
            ])
            // So the browser client can read the correlation id + the blob ETag off the response.
            .expose_headers([
                HeaderName::from_static("etag"),
                HeaderName::from_static("x-request-id"),
            ]),
    )
}

/// Does `origin` (a browser `Origin` value, e.g. `https://app.example.com`) match `pattern`?
///
/// A pattern with no `*` matches exactly. A pattern with one `*` matches a SINGLE label there — the
/// span must be non-empty and contain no `.` or `/` — so `https://*.foo.pages.dev` admits
/// `https://abc.foo.pages.dev` but never a deeper host, a path, or a look-alike suffix
/// (`https://evil-foo.pages.dev`, `https://foo.pages.dev.attacker.com`): the literal `.`/scheme in
/// the fixed parts anchor both ends.
fn origin_matches(origin: &str, pattern: &str) -> bool {
    match pattern.split_once('*') {
        None => origin == pattern,
        Some((prefix, suffix)) => {
            origin.len() > prefix.len() + suffix.len()
                && origin.starts_with(prefix)
                && origin.ends_with(suffix)
                && {
                    let mid = &origin[prefix.len()..origin.len() - suffix.len()];
                    !mid.contains('.') && !mid.contains('/')
                }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::origin_matches;

    #[test]
    fn exact_pattern_matches_only_itself() {
        let p = "https://staging.openom.org";
        assert!(origin_matches("https://staging.openom.org", p));
        assert!(!origin_matches("https://evil.openom.org", p));
        assert!(!origin_matches("http://staging.openom.org", p), "scheme must match");
        assert!(!origin_matches("https://staging.openom.org.evil.com", p));
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        let p = "https://*.proj.pages.dev";
        assert!(origin_matches("https://abc123.proj.pages.dev", p));
        assert!(origin_matches("https://x.proj.pages.dev", p));
    }

    #[test]
    fn wildcard_rejects_deeper_hosts_paths_and_lookalikes() {
        let p = "https://*.proj.pages.dev";
        assert!(!origin_matches("https://a.b.proj.pages.dev", p), "no extra label");
        assert!(!origin_matches("https://.proj.pages.dev", p), "the label must be non-empty");
        assert!(!origin_matches("https://evil-proj.pages.dev", p), "the leading dot anchors the suffix");
        assert!(!origin_matches("https://proj.pages.dev.evil.com", p), "the suffix must end the host");
        assert!(!origin_matches("https://abc.proj.pages.dev.evil.com", p));
        assert!(!origin_matches("https://abc.proj.pages.dev/", p), "an origin carries no path");
    }
}
