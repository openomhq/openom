//! OTLP EXPORT-mechanism check — the part span-content tests can't reach.
//!
//! Builds the REAL exporter from `telemetry.rs` (OTLP HTTP/protobuf over the *blocking* reqwest
//! client + a `BatchSpanProcessor`), emits a span, and runs `force_flush()` — the exact drain
//! `main.rs` performs before a Lambda freeze — against a loopback OTLP receiver, then asserts the
//! bytes actually arrived. This is what proves the async topology is sound: the blocking client
//! runs on the batch processor's own OS thread while the receiver runs on a tokio worker (hence
//! `multi_thread`) — the precise arrangement that would deadlock/silently drop spans if the exporter
//! were misconfigured (e.g. the async reqwest client under the blocking batch thread).
//!
//! `#[ignore]`d: its failure trigger is an exporter-config change or an opentelemetry/reqwest bump,
//! not per-commit app code — so it runs via `cargo test -p openom --test tracing_export -- --ignored`
//! or the `otel-export` workflow, never in the default per-push gate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use opentelemetry::trace::{Tracer, TracerProvider as _};
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "export-mechanism check — run with --ignored or via the otel-export workflow"]
async fn batch_exporter_delivers_over_http_and_force_flush_drains() {
    // 1. Loopback OTLP receiver: count POSTs to /v1/traces and the total body bytes.
    let hits = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let app = {
        let (hits, bytes) = (hits.clone(), bytes.clone());
        axum::Router::new().route(
            "/v1/traces",
            post(move |body: axum::body::Bytes| {
                let (hits, bytes) = (hits.clone(), bytes.clone());
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    bytes.fetch_add(body.len(), Ordering::SeqCst);
                    // An empty 200 is a valid OTLP/HTTP success response.
                    axum::http::StatusCode::OK
                }
            }),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // 2. The exact export path telemetry.rs builds: HTTP/protobuf, blocking reqwest client, batch processor.
    let exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(Duration::from_secs(2))
        .with_endpoint(format!("http://{addr}/v1/traces"))
        .build()
        .expect("OTLP exporter builds");
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::AlwaysOn)
        .with_batch_exporter(exporter)
        .build();

    // 3. Emit a span, then force_flush — force_flush blocks until the batch thread has POSTed and
    //    gotten its 200, so the assertions below are deterministic (no sleeps/races).
    {
        let tracer = provider.tracer("openom-export-test");
        tracer.in_span("export_smoke", |_cx| {});
    }
    provider.force_flush().expect("force_flush drains the batch to the backend");

    // 4. The receiver must have received the export with a non-empty protobuf body.
    assert!(hits.load(Ordering::SeqCst) >= 1, "OTLP receiver got no export POST — spans were dropped");
    assert!(bytes.load(Ordering::SeqCst) > 0, "export POST body was empty");
}
