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
    alert::{email::EmailSink, ntfy::NtfySink, AlertSink, LoggerSink, MultiSink},
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

    // Sinks: LoggerSink is always-on (so alerts never silently drop
    // even with broken env). NtfySink + EmailSink turn on when their
    // env vars are present. All three pass through MultiSink with
    // per-sink failure isolation.
    let mut sinks_vec: Vec<Box<dyn AlertSink>> = Vec::new();
    sinks_vec.push(Box::new(LoggerSink));

    let mut active_sink_names: Vec<&'static str> = vec!["logger"];
    match NtfySink::from_env() {
        Ok(Some(s)) => {
            sinks_vec.push(Box::new(s));
            active_sink_names.push("ntfy");
        }
        Ok(None) => {
            tracing::info!(
                "ntfy disabled (set NTFY_URL + WATCHTOWER_NTFY_TOPIC to enable)"
            );
        }
        Err(e) => {
            return Err(format!("ntfy sink misconfigured: {e}").into());
        }
    }
    match EmailSink::from_env() {
        Ok(Some(s)) => {
            sinks_vec.push(Box::new(s));
            active_sink_names.push("email");
        }
        Ok(None) => {
            tracing::info!(
                "email disabled (set WATCHTOWER_EMAIL_TO to enable; only Page-severity alerts \
                 trigger email per feedback_email_important_items)"
            );
        }
        Err(e) => {
            return Err(format!("email sink misconfigured: {e}").into());
        }
    }

    let sinks = MultiSink::new(sinks_vec);
    if sinks.is_empty() {
        return Err("no alert sinks configured — refusing to start".into());
    }

    tracing::info!(
        units = ?units,
        sink_count = sinks.len(),
        sinks = ?active_sink_names,
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
