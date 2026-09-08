use crate::cron;
use async_trait::async_trait;
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use zeroclaw_api::tool::{Tool, ToolOutput, ToolResult};
use zeroclaw_config::schema::Config;

const MAX_RUN_OUTPUT_CHARS: usize = 500;

pub struct CronRunsTool {
    config: Arc<Config>,
    /// Owning agent — run history for another agent's job is not readable.
    agent_alias: String,
}

impl CronRunsTool {
    pub fn new(config: Arc<Config>, agent_alias: impl Into<String>) -> Self {
        Self {
            config,
            agent_alias: agent_alias.into(),
        }
    }
}

#[derive(Serialize)]
struct RunView {
    id: i64,
    job_id: String,
    started_at: chrono::DateTime<chrono::Utc>,
    finished_at: chrono::DateTime<chrono::Utc>,
    status: String,
    output: Option<String>,
    duration_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    persistence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<zeroclaw_api::ingress::InternalPrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executing_agent: Option<String>,
}

#[async_trait]
impl Tool for CronRunsTool {
    fn name(&self) -> &str {
        "cron_runs"
    }

    fn description(&self) -> &str {
        "List recent run history for a cron job"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "job_id": { "type": "string" },
                "limit": { "type": "integer" }
            },
            "required": ["job_id"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        if !self.config.scheduler.enabled {
            return Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some("cron is disabled by config (scheduler.enabled=false)".to_string()),
            });
        }

        let job_id = match args.get("job_id").and_then(serde_json::Value::as_str) {
            Some(v) if !v.trim().is_empty() => v,
            _ => {
                return Ok(ToolResult {
                    success: false,
                    output: ToolOutput::default(),
                    error: Some("Missing 'job_id' parameter".to_string()),
                });
            }
        };

        // Live job: the ownership gate is the job row itself. No live job: a
        // successful auto-delete one-shot retains its run record, which stays
        // readable to its own agent through the rows' durable cleanup owner —
        // and only to it: another agent's retained history (or a row without
        // an owner) reports the same not-found error as a foreign live job.
        let job_id = match cron::get_job_for_agent(&self.config, job_id, &self.agent_alias) {
            Ok(job) => job.id,
            Err(e) => {
                let retained_own = cron::list_runs(&self.config, job_id, 1)
                    .ok()
                    .and_then(|runs| runs.into_iter().next())
                    .is_some_and(|run| run.owner_agent.as_deref() == Some(&self.agent_alias));
                if retained_own {
                    job_id.to_string()
                } else {
                    return Ok(ToolResult {
                        success: false,
                        output: ToolOutput::default(),
                        error: Some(e.to_string()),
                    });
                }
            }
        };

        let limit = args
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map_or(10, |v| usize::try_from(v).unwrap_or(10));

        match cron::list_runs(&self.config, &job_id, limit) {
            Ok(runs) => {
                let runs: Vec<RunView> = runs
                    .into_iter()
                    .map(|run| RunView {
                        id: run.id,
                        job_id: run.job_id,
                        started_at: run.started_at,
                        finished_at: run.finished_at,
                        status: run.status,
                        output: run.output.map(|out| truncate(&out, MAX_RUN_OUTPUT_CHARS)),
                        duration_ms: run.duration_ms,
                        execution: run.execution,
                        delivery: run.delivery,
                        persistence: run.persistence,
                        principal: run.principal,
                        executing_agent: run.executing_agent,
                    })
                    .collect();

                Ok(ToolResult {
                    success: true,
                    output: serde_json::to_string_pretty(&runs)?.into(),
                    error: None,
                })
            }
            Err(e) => Ok(ToolResult {
                success: false,
                output: ToolOutput::default(),
                error: Some(e.to_string()),
            }),
        }
    }
}

fn truncate(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max_chars).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use tempfile::TempDir;
    use zeroclaw_config::schema::Config;

    const TEST_AGENT: &str = "test-agent";

    async fn test_config(tmp: &TempDir) -> Arc<Config> {
        let mut config = Config {
            data_dir: tmp.path().join("data"),
            config_path: tmp.path().join("config.toml"),
            ..Config::default()
        };
        config.risk_profiles.insert(
            TEST_AGENT.to_string(),
            zeroclaw_config::schema::RiskProfileConfig::default(),
        );
        config.runtime_profiles.insert(
            TEST_AGENT.to_string(),
            zeroclaw_config::schema::RuntimeProfileConfig::default(),
        );
        config.providers.models.openrouter.insert(
            TEST_AGENT.to_string(),
            zeroclaw_config::schema::OpenRouterModelProviderConfig::default(),
        );
        config.agents.insert(
            TEST_AGENT.to_string(),
            zeroclaw_config::schema::AliasedAgentConfig {
                model_provider: format!("openrouter.{TEST_AGENT}").into(),
                risk_profile: TEST_AGENT.into(),
                runtime_profile: TEST_AGENT.into(),
                ..Default::default()
            },
        );
        tokio::fs::create_dir_all(&config.data_dir).await.unwrap();
        Arc::new(config)
    }

    #[tokio::test]
    async fn serves_retained_history_after_job_deletion() {
        // A successful auto-delete one-shot keeps its run record after the
        // job row is gone; the tool must still return it, provenance
        // included.
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let now = Utc::now();
        cron::record_run(
            &cfg,
            "retained-one-shot",
            now,
            now + ChronoDuration::milliseconds(1),
            "ok",
            cron::RunOutcomes {
                execution: "ok",
                delivery: "not_required",
                persistence: "not_bound",
            },
            cron::RunProvenance {
                principal: None,
                executing_agent: Some(TEST_AGENT),
                job_source: Some("imperative"),
            },
            Some("done"),
            1,
        )
        .unwrap();

        let tool = CronRunsTool::new(cfg.clone(), TEST_AGENT);
        let result = tool
            .execute(json!({ "job_id": "retained-one-shot" }))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output.contains("retained-one-shot"));
        assert!(result.output.contains("executing_agent"));
    }

    #[tokio::test]
    async fn cannot_read_another_agents_retained_history() {
        // A retained one-shot record owned by another agent reports the
        // same not-found error as that agent's live jobs — no existence or
        // output leak through the missing-job fallback.
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let now = Utc::now();
        cron::record_run(
            &cfg,
            "their-retained-one-shot",
            now,
            now + ChronoDuration::milliseconds(1),
            "ok",
            cron::RunOutcomes {
                execution: "ok",
                delivery: "not_required",
                persistence: "not_bound",
            },
            cron::RunProvenance {
                principal: None,
                executing_agent: Some("other-agent"),
                job_source: Some("imperative"),
            },
            Some("their-private-output"),
            1,
        )
        .unwrap();

        let tool = CronRunsTool::new(cfg.clone(), TEST_AGENT);
        let result = tool
            .execute(json!({ "job_id": "their-retained-one-shot" }))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(
            !format!("{:?}", result.output).contains("their-private-output"),
            "another agent's retained output must not leak"
        );
    }

    #[tokio::test]
    async fn lists_runs_with_truncation() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let job = cron::add_job(&cfg, TEST_AGENT, "*/5 * * * *", "echo ok").unwrap();

        let long_output = "x".repeat(1000);
        let now = Utc::now();
        cron::record_run(
            &cfg,
            &job.id,
            now,
            now + ChronoDuration::milliseconds(1),
            "ok",
            cron::RunOutcomes {
                execution: "ok",
                delivery: "not_required",
                persistence: "not_bound",
            },
            cron::RunProvenance {
                principal: None,
                executing_agent: None,
                job_source: None,
            },
            Some(&long_output),
            1,
        )
        .unwrap();

        let tool = CronRunsTool::new(cfg.clone(), TEST_AGENT);
        let result = tool
            .execute(json!({ "job_id": job.id, "limit": 5 }))
            .await
            .unwrap();

        assert!(result.success);
        assert!(result.output.contains("..."));
    }

    #[tokio::test]
    async fn errors_when_job_id_missing() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let tool = CronRunsTool::new(cfg, TEST_AGENT);
        let result = tool.execute(json!({})).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .error
                .unwrap_or_default()
                .contains("Missing 'job_id'")
        );
    }

    /// A job owned by someone else. An agent job needs no risk profile for its
    /// owner, which keeps the fixture to the ownership boundary.
    fn other_agents_job(cfg: &Config) -> crate::cron::CronJob {
        cron::add_agent_job(
            cfg,
            "other-agent",
            Some("secret_job".into()),
            crate::cron::Schedule::Cron {
                expr: "0 8 * * *".into(),
                tz: None,
            },
            "read the other agent's inbox",
            crate::cron::SessionTarget::Isolated,
            None,
            None,
            false,
            None,
            true,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn cannot_read_another_agents_run_history() {
        let tmp = TempDir::new().unwrap();
        let cfg = test_config(&tmp).await;
        let theirs = other_agents_job(&cfg);
        let now = chrono::Utc::now();
        cron::record_run(
            &cfg,
            &theirs.id,
            now,
            now,
            "ok",
            cron::RunOutcomes {
                execution: "ok",
                delivery: "not_required",
                persistence: "not_bound",
            },
            cron::RunProvenance {
                principal: None,
                executing_agent: Some("other-agent"),
                job_source: Some("imperative"),
            },
            Some("private-output"),
            5,
        )
        .unwrap();

        let tool = CronRunsTool::new(cfg.clone(), TEST_AGENT);
        let result = tool.execute(json!({"job_id": theirs.id})).await.unwrap();

        assert!(!result.success);
        assert!(
            !format!("{:?}", result.output).contains("private-output"),
            "another agent's job output must not leak"
        );
    }
}
