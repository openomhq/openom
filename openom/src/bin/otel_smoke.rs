//! `otel_smoke` — a live check that OTLP export works end-to-end against the configured backend
//! (Axiom in staging) AND that W3C trace-context propagation links spans across a service boundary.
//!
//! It emits ONE trace with two spans through the *real* [`openom::telemetry`] exporter:
//!   - a root **client** span (service A), then
//!   - a **server** child span whose parent is recovered from an injected → extracted `traceparent`
//!     carrier — the exact inject/extract loop a real distributed call uses.
//!
//! If Axiom shows both under one trace id, export + propagation both work (and the resource
//! attributes `service.name` / `deployment.environment.name` / `openom.stack` are populated).
//!
//! Run with the exporter configured (no DB/S3 needed — this only touches telemetry):
//!
//! ```text
//! OPENOM_OTEL=1  OTEL_EXPORTER_OTLP_ENDPOINT=<base>  OTEL_EXPORTER_OTLP_HEADERS=<k=v,..>
//! OPENOM_ENV=staging  OPENOM_STACK=otel-smoke
//! ```

use std::collections::HashMap;

use openom::config::Config;
use openom::telemetry;
use opentelemetry::propagation::{Extractor, Injector};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::prelude::*;

fn main() {
    // The same propagator the server installs, so inject/extract behaves identically here.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let config = Config::from_env();
    let provider = telemetry::build_tracer_provider(&config).expect(
        "otel_smoke needs OPENOM_OTEL=1 + OTEL_EXPORTER_OTLP_ENDPOINT + OTEL_EXPORTER_OTLP_HEADERS",
    );
    let otel_layer = {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer("openom"))
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    // Service A: a root "client" span, and the `traceparent` it would send downstream.
    let mut carrier: HashMap<String, String> = HashMap::new();
    tracing::info_span!("otel_smoke.client", otel.kind = "client").in_scope(|| {
        tracing::info!("otel_smoke: emitting the client span");
        let cx = tracing::Span::current().context();
        opentelemetry::global::get_text_map_propagator(|prop| {
            prop.inject_context(&cx, &mut MapInjector(&mut carrier));
        });
    });

    // Service B: recover the parent from the carrier (exactly as the server's make_span does) and
    // continue the same trace with a "server" child span.
    let parent = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&MapExtractor(&carrier))
    });
    let server = tracing::info_span!(
        "otel_smoke.server",
        otel.kind = "server",
        http.route = "/otel-smoke",
        request_id = "otel-smoke"
    );
    if let Err(err) = server.set_parent(parent) {
        eprintln!("otel_smoke: could not attach parent context: {err:?}");
    }
    server.in_scope(|| {
        tracing::info!("otel_smoke: emitting the server span, linked to the client span");
    });

    provider.force_flush().expect("flush spans to the backend");
    println!("otel_smoke: sent a 2-span trace (client -> server) and flushed — check Axiom.");
}

/// Write W3C propagation fields into a plain map (the "outgoing request headers").
struct MapInjector<'a>(&'a mut HashMap<String, String>);
impl Injector for MapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

/// Read W3C propagation fields back out of the map (the "incoming request headers").
struct MapExtractor<'a>(&'a HashMap<String, String>);
impl Extractor for MapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}
