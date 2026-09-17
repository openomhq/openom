//! HTTP request tracing.
//!
//! One SERVER root span per request (exported over OTLP by [`crate::telemetry`]), W3C
//! trace-context continuation so an incoming `traceparent` keeps the SAME trace across the
//! client → server → downstream hop, and a correlatable `x-request-id` threaded through the
//! span, the logs, and the response header. `tracing` stays the only API app code touches;
//! this module is the seam that turns each request into a root span and a correlation id.

use std::time::Duration;

use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response};
use axum::middleware::Next;
use axum::Router;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TraceContextExt;
use tower_http::trace::TraceLayer;
use tracing::field::Empty;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

/// The correlation header (lower-case: HTTP/2 requires it; `http::HeaderName` is case-insensitive).
const REQUEST_ID: &str = "x-request-id";

/// Accept a caller-supplied id only if it's a bounded, safe token — else we mint our own. Caps
/// size/cardinality and keeps only characters that are inert in logs and downstream headers.
fn is_valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Ensure every request carries an `x-request-id` — reuse the caller's, else mint a UUID — and
/// echo it on the response so the client can correlate its call with our logs/traces. Runs
/// OUTSIDE the trace layer so the id is already present when the span is built.
pub(crate) async fn request_id(mut req: Request, next: Next) -> Response<Body> {
    let id = req
        .headers()
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned);
    // A caller-supplied id with illegal header bytes is dropped rather than failing the request.
    let Ok(value) = HeaderValue::from_str(&id) else {
        return next.run(req).await;
    };
    req.headers_mut().insert(REQUEST_ID, value.clone());
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(REQUEST_ID, value);
    resp
}

/// Build the root SERVER span: method + matched route (low-cardinality, no PII or query strings —
/// SERVER-DATA-FORMAT §7) + the request id, with its parent taken from any incoming W3C trace
/// context so distributed traces stay linked. `tracing-opentelemetry` reads the `otel.*` fields.
pub(crate) fn make_span(req: &Request) -> Span {
    let request_id = req
        .headers()
        .get(REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let method = req.method().as_str();
    // Matched route only (`/v1/trees/{id}`) — never the concrete/probed path, which is unbounded
    // cardinality and can carry scanner junk / PII-ish payloads (SERVER-DATA-FORMAT §7). Unmatched
    // (404/fallback) requests collapse to one constant name.
    let matched = req.extensions().get::<MatchedPath>().map(MatchedPath::as_str);
    let route = matched.unwrap_or_default();
    let otel_name = match matched {
        Some(r) => format!("{method} {r}"),
        None => format!("{method} <unmatched>"),
    };

    let span = tracing::info_span!(
        "http.request",
        otel.name = %otel_name,
        otel.kind = "server",
        otel.status_code = Empty,
        http.request.method = %method,
        http.route = %route,
        request_id = %request_id,
        http.response.status_code = Empty,
    );
    // Continue an incoming distributed trace ONLY when the caller sent a valid W3C `traceparent`:
    // extract() yields an empty context for a missing/garbage header, and pinning that as the
    // parent would both log spuriously (every request when OTEL is off) and force an empty root.
    let parent = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderExtractor(req.headers()))
    });
    if parent.span().span_context().is_valid() {
        if let Err(err) = span.set_parent(parent) {
            tracing::debug!(error = ?err, "ignoring incoming trace context");
        }
    }
    span
}

/// Stamp the response status onto the request span; mark 5xx as an error span (OTEL status).
/// 4xx stays OK — a client error is not a server fault (OTEL span-status convention).
pub(crate) fn on_response(res: &Response<Body>, _latency: Duration, span: &Span) {
    let status = res.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
}

/// Apply the request-tracing layers to a router: the SERVER span ([`make_span`]/[`on_response`])
/// and the [`request_id`] middleware (applied last = OUTERMOST, so the id is present when the span
/// is built and is echoed on the response). Extracted so `app()` and the tracing tests share ONE
/// wiring — the test proves span/route/status/id behavior on a stateless router, and `app()` can't
/// silently drift from it (a companion `api.rs` assertion checks the real `app()` still applies it).
pub fn with_trace_layers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_span)
                .on_response(on_response),
        )
        .layer(axum::middleware::from_fn(request_id))
}

/// Adapt an HTTP `HeaderMap` to OpenTelemetry's propagation `Extractor` — so we can read W3C
/// `traceparent`/`tracestate` without pulling in `opentelemetry-http` just for this.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}
