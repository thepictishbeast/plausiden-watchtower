//! Classify parsed log events into alert-worthy buckets.
//!
//! The classifier is a sliding-window threshold engine. Each rule has a
//! window (e.g. 60s), a count, and a key extractor (e.g. "FATAL anywhere"
//! vs "ERROR per chain" vs "REJECT cluster per step"). When events
//! arriving within the window cross the count, the rule fires once;
//! it then enters a per-rule cooldown so a sustained burst doesn't
//! pager-storm.
//!
//! All time is `chrono::Utc` so we can replay historical journal logs
//! and have the classifier produce identical decisions to a live run.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::parse::{Level, LogEvent, StructuredEvent};

/// Severity of a fired classification — drives sink dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Aggregate / informational. Logged only.
    Info,
    /// Concerning trend. Sent to ntfy at low priority.
    Warn,
    /// Page the operator. Goes to ntfy + email.
    Page,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub severity: Severity,
    pub rule: String,
    pub key: String,
    pub count: usize,
    pub window_secs: i64,
    pub sample_event: Option<StructuredEvent>,
    pub fired_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct Rule {
    name: &'static str,
    severity: Severity,
    window: Duration,
    threshold: usize,
    cooldown: Duration,
    matches: fn(&StructuredEvent) -> Option<String>,
}

/// Built-in rule set. Order matters only for tie-breaking; each rule
/// fires independently.
fn builtin_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "fatal_any",
            severity: Severity::Page,
            window: Duration::seconds(86_400),
            threshold: 1,
            cooldown: Duration::seconds(300),
            matches: |e| {
                if e.level == Level::Fatal {
                    Some("any".into())
                } else {
                    None
                }
            },
        },
        Rule {
            name: "error_burst_per_chain",
            severity: Severity::Page,
            window: Duration::seconds(60),
            threshold: 5,
            cooldown: Duration::seconds(300),
            matches: |e| {
                if e.level == Level::Error {
                    Some(e.chain.clone().unwrap_or_else(|| "unspecified".into()))
                } else {
                    None
                }
            },
        },
        Rule {
            name: "error_baseline_per_chain",
            severity: Severity::Warn,
            window: Duration::seconds(600),
            threshold: 1,
            cooldown: Duration::seconds(600),
            matches: |e| {
                if e.level == Level::Error {
                    Some(e.chain.clone().unwrap_or_else(|| "unspecified".into()))
                } else {
                    None
                }
            },
        },
        Rule {
            name: "reject_cluster_per_step",
            severity: Severity::Warn,
            window: Duration::seconds(60),
            threshold: 10,
            cooldown: Duration::seconds(300),
            matches: |e| {
                if e.message.contains("REJECT") {
                    let step = e.step.clone().unwrap_or_else(|| "unspecified".into());
                    let chain = e.chain.clone().unwrap_or_else(|| "any".into());
                    Some(format!("{chain}::{step}"))
                } else {
                    None
                }
            },
        },
        Rule {
            name: "warn_baseline_global",
            severity: Severity::Info,
            window: Duration::seconds(600),
            threshold: 50,
            cooldown: Duration::seconds(600),
            matches: |e| {
                if e.level == Level::Warn {
                    Some("global".into())
                } else {
                    None
                }
            },
        },
    ]
}

#[derive(Debug)]
struct WindowState {
    /// Timestamps of events matching the rule's key, oldest-first.
    events: VecDeque<(DateTime<Utc>, StructuredEvent)>,
    last_fired: Option<DateTime<Utc>>,
}

impl WindowState {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            last_fired: None,
        }
    }
}

#[derive(Debug)]
pub struct Classifier {
    rules: Vec<Rule>,
    /// State per (rule_name, key).
    states: HashMap<(&'static str, String), WindowState>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self {
            rules: builtin_rules(),
            states: HashMap::new(),
        }
    }
}

impl Classifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one event. Returns any alerts that fired (zero or more).
    ///
    /// `now` is supplied so tests can drive the clock deterministically;
    /// production passes `Utc::now()`.
    pub fn ingest(&mut self, event: &LogEvent, now: DateTime<Utc>) -> Vec<Alert> {
        let LogEvent::Structured(structured) = event else {
            return Vec::new();
        };

        let mut fired = Vec::new();

        for rule in &self.rules {
            let Some(key) = (rule.matches)(structured) else {
                continue;
            };
            let state = self
                .states
                .entry((rule.name, key.clone()))
                .or_insert_with(WindowState::new);

            // Drop events older than the window before adding the new one.
            let cutoff = now - rule.window;
            while let Some((ts, _)) = state.events.front() {
                if *ts < cutoff {
                    state.events.pop_front();
                } else {
                    break;
                }
            }

            state.events.push_back((now, structured.clone()));

            // Fire if threshold reached AND not in cooldown.
            if state.events.len() >= rule.threshold {
                let in_cooldown = state
                    .last_fired
                    .is_some_and(|last| now - last < rule.cooldown);
                if !in_cooldown {
                    state.last_fired = Some(now);
                    fired.push(Alert {
                        severity: rule.severity,
                        rule: rule.name.into(),
                        key: key.clone(),
                        count: state.events.len(),
                        window_secs: rule.window.num_seconds(),
                        sample_event: state.events.back().map(|(_, e)| e.clone()),
                        fired_at: now,
                    });
                }
            }
        }

        fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_line;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn structured(line: &str) -> LogEvent {
        parse_line(line)
    }

    #[test]
    fn fatal_fires_immediately() {
        let mut c = Classifier::new();
        let e = structured("[3:55:50 PM] [FATAL] [storage] postgres unreachable");
        let alerts = c.ingest(&e, t("2026-05-01T12:00:00Z"));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "fatal_any");
        assert_eq!(alerts[0].severity, Severity::Page);
    }

    #[test]
    fn error_burst_threshold_five_per_chain() {
        let mut c = Classifier::new();
        let line = "[3:55:50 PM] [ERROR] [registration] chain=registration rid=r1 step=POST /api/register 1/8 db error";
        let now = t("2026-05-01T12:00:00Z");
        for i in 0..4 {
            let alerts = c.ingest(&structured(line), now + Duration::seconds(i));
            // First 4 must NOT page (threshold is 5)
            assert!(
                alerts.iter().all(|a| a.rule != "error_burst_per_chain"),
                "iteration {i} fired prematurely: {alerts:?}"
            );
        }
        let alerts = c.ingest(&structured(line), now + Duration::seconds(4));
        let burst = alerts.iter().find(|a| a.rule == "error_burst_per_chain");
        assert!(burst.is_some(), "5th error must fire burst rule");
        assert_eq!(burst.unwrap().key, "registration");
    }

    #[test]
    fn cooldown_suppresses_repeated_firing() {
        let mut c = Classifier::new();
        let line = "[3:55:50 PM] [FATAL] [storage] postgres unreachable";
        let t0 = t("2026-05-01T12:00:00Z");
        let a1 = c.ingest(&structured(line), t0);
        assert_eq!(a1.len(), 1);
        // 1s later — within cooldown — must NOT fire.
        let a2 = c.ingest(&structured(line), t0 + Duration::seconds(1));
        assert!(a2.iter().all(|a| a.rule != "fatal_any"));
        // After cooldown — fires again.
        let a3 = c.ingest(&structured(line), t0 + Duration::seconds(301));
        assert!(a3.iter().any(|a| a.rule == "fatal_any"));
    }

    #[test]
    fn separate_chains_have_separate_windows() {
        let mut c = Classifier::new();
        let reg_line = "[3:55:50 PM] [ERROR] [registration] chain=registration error one";
        let zk_line = "[3:55:50 PM] [ERROR] [zktls] chain=zktls error two";
        let now = t("2026-05-01T12:00:00Z");
        // 4 reg + 4 zktls — neither hits the burst threshold of 5.
        for i in 0..4 {
            let _ = c.ingest(&structured(reg_line), now + Duration::seconds(i));
            let _ = c.ingest(&structured(zk_line), now + Duration::seconds(i));
        }
        // 5th reg fires; zktls must NOT.
        let alerts = c.ingest(&structured(reg_line), now + Duration::seconds(5));
        let burst: Vec<_> = alerts.iter().filter(|a| a.rule == "error_burst_per_chain").collect();
        assert_eq!(burst.len(), 1);
        assert_eq!(burst[0].key, "registration");
    }

    #[test]
    fn reject_cluster_per_step_fires_at_ten() {
        let mut c = Classifier::new();
        let line = "[3:55:50 PM] [WARN] [security] chain=registration rid=r1 step=POST /api/register 5/8 REJECT duplicate piiHash";
        let now = t("2026-05-01T12:00:00Z");
        for i in 0..9 {
            let alerts = c.ingest(&structured(line), now + Duration::seconds(i));
            assert!(alerts.iter().all(|a| a.rule != "reject_cluster_per_step"));
        }
        let alerts = c.ingest(&structured(line), now + Duration::seconds(9));
        assert!(alerts.iter().any(|a| a.rule == "reject_cluster_per_step"));
    }

    #[test]
    fn unstructured_lines_produce_no_alerts() {
        let mut c = Classifier::new();
        let alerts = c.ingest(
            &LogEvent::Unstructured { raw: "kernel: oom-killer".into() },
            t("2026-05-01T12:00:00Z"),
        );
        assert!(alerts.is_empty());
    }

    #[test]
    fn old_events_drop_out_of_window() {
        let mut c = Classifier::new();
        let line = "[3:55:50 PM] [ERROR] [reg] chain=registration error";
        let t0 = t("2026-05-01T12:00:00Z");
        // 4 errors at t0
        for i in 0..4 {
            let _ = c.ingest(&structured(line), t0 + Duration::milliseconds(i * 100));
        }
        // 1 more 70 seconds later — first 4 dropped out of the 60s window;
        // count is now 1, threshold is 5, must NOT fire.
        let alerts = c.ingest(&structured(line), t0 + Duration::seconds(70));
        assert!(alerts.iter().all(|a| a.rule != "error_burst_per_chain"));
    }

    #[test]
    fn error_without_chain_uses_unspecified_bucket() {
        let mut c = Classifier::new();
        let line = "[3:55:50 PM] [ERROR] [some-source] no chain on this one";
        let t0 = t("2026-05-01T12:00:00Z");
        // Five errors with no chain — must fire under the "unspecified" key.
        for i in 0..4 {
            let _ = c.ingest(&structured(line), t0 + Duration::seconds(i));
        }
        let alerts = c.ingest(&structured(line), t0 + Duration::seconds(4));
        let burst = alerts.iter().find(|a| a.rule == "error_burst_per_chain");
        assert!(burst.is_some());
        assert_eq!(burst.unwrap().key, "unspecified");
    }
}
