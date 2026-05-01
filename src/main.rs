//! plausiden-watchtower daemon entry point.
//!
//! Wires journalctl tailers to the parser → classifier → sink pipeline.
//!
//! CLI is intentionally small for the scaffold; sink wiring (#316) and
//! the auto-fix loop (#317) extend this. The daemon refuses to start
//! without at least one configured alert sink so a misconfiguration
//! can never silently lose alerts.

#[cfg(feature = "journal")]
use chrono::Utc;
#[cfg(feature = "journal")]
use plausiden_watchtower::{
    alert::{AlertSink, LoggerSink, MultiSink},
    classify::Classifier,
    journal,
    parse::parse_line,
};

#[cfg(feature = "journal")]
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "plausiden_watchtower=info,warn".into()),
        )
        .init();

    let units: Vec<String> = std::env::var("WATCHTOWER_UNITS")
        .unwrap_or_else(|_| {
            // Default: every Sacred Vote service that emits chain logs.
            "sacredvote,sacredvote-identity,sacredvote-zktls,sacredvote-webauthn,\
             sacredvote-crypto,sacredvote-analytics"
                .into()
        })
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if units.is_empty() {
        return Err("WATCHTOWER_UNITS empty — refusing to start".into());
    }

    // For #315 the only sink is LoggerSink. #316 adds ntfy + email and
    // promotes the "at least one sink" check from a no-op to an
    // operational gate.
    let sinks = MultiSink::new(vec![Box::new(LoggerSink)]);
    if sinks.is_empty() {
        return Err("no alert sinks configured — refusing to start".into());
    }

    tracing::info!(
        units = ?units,
        sinks = sinks.len(),
        "watchtower starting"
    );

    let mut classifier = Classifier::new();
    let mut rx = journal::spawn(units, None)?;

    while let Some((unit, raw)) = rx.recv().await {
        let event = parse_line(&raw);
        let alerts = classifier.ingest(&event, Utc::now());
        for alert in alerts {
            tracing::info!(
                unit = %unit,
                rule = %alert.rule,
                key = %alert.key,
                count = alert.count,
                "alert fired"
            );
            if let Err(e) = sinks.dispatch(&alert).await {
                tracing::error!(error = %e, "sink dispatch error");
            }
        }
    }

    tracing::warn!("journal channel closed — watchtower exiting");
    Ok(())
}

#[cfg(not(feature = "journal"))]
fn main() {
    eprintln!(
        "plausiden-watchtower binary requires the `journal` feature.\n\
         Build with: cargo build --features journal --release"
    );
    std::process::exit(2);
}
