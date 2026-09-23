//! openom server binary — a thin shell over the `openom` library: initialize
//! tracing, build shared state, and serve (local HTTP or Lambda). The app, routes,
//! state, and startup wiring live in `lib.rs` so they're testable in-process.

use openom::config::Config;
use openom::{app, build_state, telemetry};
use opentelemetry_sdk::trace::SdkTracerProvider;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    let config = Config::from_env();
    let otel = init_tracing(&config);

    tracing::info!(
        runtime = ?config.runtime,
        storage = ?config.storage,
        auth = ?config.auth,
        envelope_version = openom_protocol::ENVELOPE_VERSION,
        ciphers = openom_crypto::cipher_suite(),
        "openom starting"
    );

    let state = build_state(&config).await?;
    let router = app(state);

    if config.is_remote() {
        // The lambda_runtime OTel layer wraps the whole invocation: it drops the handler future
        // (closing the request span so it's included in the flush) and flushes AFTER the response
        // is posted to the runtime — so the flush is OFF the client-latency path, and the last span
        // before a sandbox freeze isn't lost. (The batch processor's own timer stops when frozen.)
        match otel.clone() {
            Some(provider) => {
                use lambda_runtime::layers::{OpenTelemetryFaasTrigger, OpenTelemetryLayer};
                use lambda_runtime::Runtime;
                let flush = move || {
                    if let Err(err) = provider.force_flush() {
                        tracing::warn!(error = ?err, "OTLP span flush failed");
                    }
                };
                Runtime::new(lambda_http::Adapter::from(router))
                    .layer(
                        OpenTelemetryLayer::new(flush).with_trigger(OpenTelemetryFaasTrigger::Http),
                    )
                    .run()
                    .await
            }
            None => lambda_http::run(router).await,
        }
    } else {
        let addr = config.http_addr.clone();
        tracing::info!(%addr, "serving locally over plain HTTP");
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, router).await?;
        Ok(())
    }
}

/// Build the subscriber: an `EnvFilter`, a `fmt` layer (pretty local / JSON prod),
/// and — only when `OPENOM_OTEL` is set — a `tracing-opentelemetry` layer exporting
/// over OTLP. App code speaks plain `tracing` macros and never knows which backend is
/// attached; this composition root is the only place the choice is made. Returns the
/// tracer provider (when enabled) so the caller can flush it on Lambda.
fn init_tracing(config: &Config) -> Option<SdkTracerProvider> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter, Layer};

    // Install the W3C trace-context propagator so an incoming `traceparent` continues the same
    // trace (and outgoing calls can inject it, once wired) — the standard for distributed traces.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let provider = telemetry::build_tracer_provider(config);
    let otel_layer = provider.as_ref().map(|p| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(p.tracer("openom"))
    });

    let fmt_layer = if config.is_remote() {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    provider
}
