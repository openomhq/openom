//! Server request-tracing contract — hermetic, no DB/network, runs in the default unit gate.
//!
//! Drives requests through the REAL trace layers ([`openom::with_trace_layers`], the same wiring
//! `app()` uses) on a minimal but *nested* router, capturing spans with an in-memory exporter, and
//! asserts what `http_trace.rs` promises: one SERVER span per request with the matched route (incl.
//! nested), the response status (5xx → error span), a correlatable `x-request-id`, W3C parent
//! continuation, and — critically — that a caller's `sampled=0` never suppresses our own span.
//!
//! Isolation: this is its own test binary, so the process-global tracing subscriber is ours alone;
//! tests run concurrently and share one exporter, so every assertion filters spans by the unique
//! `x-request-id` it sent (never by index/count).

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use opentelemetry::trace::{SpanKind, Status, TracerProvider as _};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{
    InMemorySpanExporter, InMemorySpanExporterBuilder, Sampler, SdkTracerProvider, SpanData,
};
use tower::ServiceExt;
use tracing_subscriber::prelude::*;

/// A fixed valid W3C trace id we send as the caller's `traceparent` and expect the server span to keep.
const CALLER_TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
const CALLER_SPAN_ID: &str = "b7ad6b7169203331";

struct Harness {
    router: Router,
    exporter: InMemorySpanExporter,
    // Held only to keep the provider (and thus the exporting tracer) alive for the whole run;
    // dropping it would shut the processor down.
    _provider: SdkTracerProvider,
}

/// Built once per process: the propagator + a synchronous in-memory exporter installed as the global
/// subscriber, and the router with the real trace layers applied.
static HARNESS: LazyLock<Harness> = LazyLock::new(|| {
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        // Mirror telemetry.rs EXACTLY: AlwaysOn (not the SDK-default ParentBased) so a caller's
        // sampled=0 can't drop our span — and so SimpleSpanProcessor doesn't silently discard it.
        .with_sampler(Sampler::AlwaysOn)
        // Synchronous export on span-close → deterministic (no batch timer), and no force_flush needed.
        .with_simple_exporter(exporter.clone())
        .build();
    let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("openom-test"));
    tracing_subscriber::registry().with(otel_layer).init();

    // A real router (routing + a NESTED sub-router) so `MatchedPath` composes exactly as it does in
    // `app()`'s `.nest("/v1", …)` — a flat stub would not exercise the nested `http.route` path.
    let v1 = Router::new().route("/probe/{id}", get(|| async { "probe" }));
    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
        .nest("/v1", v1);
    let router = openom::with_trace_layers(router);

    Harness { router, exporter, _provider: provider }
});

/// One in-process request. Returns status + response headers, and — crucially — fully consumes and
/// DROPS the response body so the `TraceLayer` span (which lives in the body wrapper) closes and the
/// `SimpleSpanProcessor` exports it before the caller reads the exporter.
async fn send(req: Request<Body>) -> (StatusCode, HeaderMap) {
    let resp = HARNESS.router.clone().oneshot(req).await.expect("router is infallible");
    let status = resp.status();
    let headers = resp.headers().clone();
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, headers)
}

fn get_with_id(uri: &str, request_id: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-request-id", request_id)
        .body(Body::empty())
        .unwrap()
}

/// A string-valued span attribute, if present.
fn attr(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.to_string())
}

/// The single finished span carrying `request_id` — isolates this test's span from the concurrently
/// running ones sharing the exporter. Asserts exactly one exists.
fn span_for(request_id: &str) -> SpanData {
    let mut found: Vec<SpanData> = HARNESS
        .exporter
        .get_finished_spans()
        .expect("exporter")
        .into_iter()
        .filter(|s| attr(s, "request_id").as_deref() == Some(request_id))
        .collect();
    assert_eq!(found.len(), 1, "exactly one exported span for request_id={request_id}");
    found.pop().unwrap()
}

#[tokio::test]
async fn health_span_has_route_status_and_echoes_request_id() {
    let id = "t-health";
    let (status, headers) = send(get_with_id("/health", id)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-request-id").unwrap(), id, "the id is echoed on the response");

    let s = span_for(id);
    assert_eq!(s.name, "GET /health", "span name is method + matched route");
    assert_eq!(s.span_kind, SpanKind::Server);
    assert_eq!(attr(&s, "http.route").as_deref(), Some("/health"));
    assert_eq!(attr(&s, "http.request.method").as_deref(), Some("GET"));
    assert_eq!(attr(&s, "http.response.status_code").as_deref(), Some("200"));
    assert!(!matches!(s.status, Status::Error { .. }), "a 2xx is not an error span");
}

#[tokio::test]
async fn nested_route_records_the_full_matched_path() {
    let id = "t-nested";
    send(get_with_id("/v1/probe/42", id)).await;

    let s = span_for(id);
    // The whole point of nesting the test router: http.route must be the composed template, not
    // the concrete path (no PII/cardinality) and not the un-prefixed sub-route.
    assert_eq!(attr(&s, "http.route").as_deref(), Some("/v1/probe/{id}"));
    assert_eq!(s.name, "GET /v1/probe/{id}");
}

#[tokio::test]
async fn server_error_marks_the_span_as_error() {
    let id = "t-boom";
    let (status, _) = send(get_with_id("/boom", id)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let s = span_for(id);
    assert_eq!(attr(&s, "http.response.status_code").as_deref(), Some("500"));
    assert!(matches!(s.status, Status::Error { .. }), "a 5xx is an error span");
}

#[tokio::test]
async fn incoming_traceparent_continues_the_same_trace() {
    let id = "t-parent";
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .header("x-request-id", id)
        .header("traceparent", format!("00-{CALLER_TRACE_ID}-{CALLER_SPAN_ID}-01"))
        .body(Body::empty())
        .unwrap();
    send(req).await;

    let s = span_for(id);
    assert_eq!(
        s.span_context.trace_id().to_string(),
        CALLER_TRACE_ID,
        "server span joins the caller's trace"
    );
}

#[tokio::test]
async fn caller_sampled_zero_does_not_suppress_our_span() {
    // The one line of make_span's contract this whole file exists to protect: an untrusted client
    // sending sampled=0 must NOT switch off server-side tracing. With AlwaysOn this span still exports.
    let id = "t-sampled0";
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .header("x-request-id", id)
        .header("traceparent", format!("00-{CALLER_TRACE_ID}-{CALLER_SPAN_ID}-00"))
        .body(Body::empty())
        .unwrap();
    send(req).await;

    let s = span_for(id); // asserts exactly one span exists despite sampled=0
    assert_eq!(s.span_context.trace_id().to_string(), CALLER_TRACE_ID);
}

#[tokio::test]
async fn unmatched_path_collapses_to_a_constant_name() {
    // The cardinality/PII guard: a probed/unknown path must never enter the span name/route verbatim.
    let id = "t-unmatched";
    let (status, _) = send(get_with_id("/no/such/route/12345", id)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let s = span_for(id);
    assert_eq!(s.name, "GET <unmatched>", "unmatched requests collapse to one constant name");
    assert_eq!(attr(&s, "http.route").as_deref(), Some(""), "no route template for an unmatched path");
}
