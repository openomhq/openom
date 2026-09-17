//! OTLP export wiring.
//!
//! The `tracing` macros stay the *only* instrumentation API the app ever touches —
//! this module just turns their spans into OTLP when `OPENOM_OTEL` is set, pointed
//! at grafana/otel-lgtm (dev) or Axiom (prod) by config. Everything here is
//! inert unless [`build_tracer_provider`] returns `Some`, so a plain local run pays
//! nothing. Export is HTTP/protobuf over reqwest+rustls — no gRPC/tonic, no OpenSSL.

use std::collections::HashMap;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;

use crate::config::Config;

/// Build a batch-exporting tracer provider, or `None` when telemetry is off (or the
/// exporter can't be constructed — telemetry must never take the server down).
///
/// The
/// caller attaches it as a `tracing` layer and holds it to `force_flush` on Lambda.
#[must_use]
pub fn build_tracer_provider(config: &Config) -> Option<SdkTracerProvider> {
    if !config.otel_enabled {
        return None;
    }
    let mut builder = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        // Bound export: a slow/unreachable backend must not stall force_flush (hard-capped 5s) —
        // and, on Lambda, the per-invocation flush — for the full default 10s.
        .with_timeout(Duration::from_secs(2))
        .with_endpoint(traces_endpoint(&config.otlp_endpoint));
    if let Some(raw) = &config.otlp_headers {
        builder = builder.with_headers(parse_headers(raw));
    }
    match builder.build() {
        Ok(exporter) => Some(
            SdkTracerProvider::builder()
                // Always record our own root span: an untrusted client's `traceparent` sampled=0
                // flag must never suppress server-side tracing (the ParentBased default would honor
                // it). We keep the caller's trace id for continuity, not its sampling veto.
                .with_sampler(Sampler::AlwaysOn)
                // Batch, not per-span: on Lambda a per-invocation force_flush drains
                // it before the sandbox freezes (main.rs); locally the batch timer
                // flushes on its own.
                .with_batch_exporter(exporter)
                .with_resource(build_resource(config))
                .build(),
        ),
        Err(err) => {
            // tracing isn't initialized yet at this point, so go straight to stderr.
            eprintln!("openom: OTLP exporter init failed ({err}); continuing without span export");
            None
        }
    }
}

/// The OTLP resource: `service.name` plus the env-identity attributes so dashboards can
/// filter by environment and separate one deploy's telemetry from another's.
fn build_resource(config: &Config) -> Resource {
    // OTEL semconv (v1.27+): which environment emitted this span.
    let mut attrs = vec![KeyValue::new(
        "deployment.environment.name",
        config.env.as_str().to_string(),
    )];
    if let Some(stack) = &config.stack {
        // A shared per-deploy label — deliberately NOT `service.instance.id` (semconv reserves that
        // for a value unique per running process; N Lambda sandboxes would collide). Custom
        // namespace so backends don't mis-group by it.
        attrs.push(KeyValue::new("openom.stack", stack.clone()));
    }
    Resource::builder()
        .with_service_name("openom")
        .with_attributes(attrs)
        .build()
}

/// OTLP/HTTP wants the signal path; accept either a base (`…:4318`) or a full
/// traces endpoint and normalize to `…/v1/traces`.
fn traces_endpoint(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/v1/traces") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/v1/traces")
    }
}

/// Parse `k1=v1,k2=v2` OTLP headers (e.g. an Axiom API token + dataset). Values are
/// secret and never logged.
fn parse_headers(raw: &str) -> HashMap<String, String> {
    raw.split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}
