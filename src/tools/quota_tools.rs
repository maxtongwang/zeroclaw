//! Built-in tools for quota monitoring and provider management.
//!
//! These tools allow the agent to:
//! - Check quota status conversationally
//! - Switch providers when rate limited
//! - Estimate quota costs before operations
//! - Report usage metrics to the user

use crate::auth::profiles::AuthProfilesStore;
use crate::config::Config;
use crate::providers::health::ProviderHealthTracker;
use crate::providers::quota_types::{QuotaStatus, QuotaSummary};
use crate::tools::{Tool, ToolResult};
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

/// Tool for checking provider quota status.
///
/// Allows agent to query: "какие модели доступны?" or "what providers have quota?"
pub struct CheckProviderQuotaTool {
    config: Arc<Config>,
}

impl CheckProviderQuotaTool {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    async fn build_quota_summary(&self, provider_filter: Option<&str>) -> Result<QuotaSummary> {
        // Initialize health tracker with same settings as reliable.rs
        let health_tracker = ProviderHealthTracker::new(
            3,                       // failure_threshold
            Duration::from_secs(60), // cooldown
            100,                     // max tracked providers
        );

        // Load OAuth profiles
        let auth_store =
            AuthProfilesStore::new(&self.config.workspace_dir, self.config.secrets.encrypt);
        let profiles_data = auth_store.load().await?;

        // Build quota summary using quota_cli logic
        crate::providers::quota_cli::build_quota_summary(
            &health_tracker,
            &profiles_data,
            provider_filter,
        )
    }
}

#[async_trait]
impl Tool for CheckProviderQuotaTool {
    fn name(&self) -> &str {
        "check_provider_quota"
    }

    fn description(&self) -> &str {
        "Check current rate limit and quota status for AI providers. \
         Returns available providers, rate-limited providers, quota remaining, \
         and estimated reset time. Use this when user asks about model availability \
         or when you encounter rate limit errors."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Specific provider to check (optional). Examples: openai, gemini, anthropic. If omitted, checks all providers."
                }
            }
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        let provider_filter = args.get("provider").and_then(|v| v.as_str());

        let summary = self.build_quota_summary(provider_filter).await?;

        // Format result for agent
        let available = summary.available_providers();
        let rate_limited = summary.rate_limited_providers();
        let circuit_open = summary.circuit_open_providers();

        let mut output = String::new();
        let _ = write!(
            output,
            "📊 Quota Status ({})\n\n",
            summary.timestamp.format("%Y-%m-%d %H:%M UTC")
        );

        if !available.is_empty() {
            let _ = writeln!(
                output,
                "✅ Available providers: {}",
                available.join(", ")
            );
        }
        if !rate_limited.is_empty() {
            let _ = writeln!(
                output,
                "⚠️  Rate-limited providers: {}",
                rate_limited.join(", ")
            );
        }
        if !circuit_open.is_empty() {
            let _ = writeln!(
                output,
                "❌ Circuit-open providers: {}",
                circuit_open.join(", ")
            );
        }

        if available.is_empty() && rate_limited.is_empty() && circuit_open.is_empty() {
            output.push_str(
                "ℹ️  No quota information available. Quota is populated after API calls.\n",
            );
        }

        // Add details for each provider
        for provider_info in &summary.providers {
            if provider_filter.is_some() || provider_info.status != QuotaStatus::Ok {
                let _ = write!(
                    output,
                    "\n📍 {}: {:?}\n",
                    provider_info.provider, provider_info.status
                );

                if provider_info.failure_count > 0 {
                    let _ = writeln!(output, "   Failures: {}", provider_info.failure_count);
                }

                if let Some(retry_after) = provider_info.retry_after_seconds {
                    let _ = writeln!(output, "   Retry after: {}s", retry_after);
                }

                for profile in &provider_info.profiles {
                    if let Some(remaining) = profile.rate_limit_remaining {
                        if let Some(total) = profile.rate_limit_total {
                            let _ = writeln!(
                                output,
                                "   {}: {}/{} requests",
                                profile.profile_name, remaining, total
                            );
                        } else {
                            let _ = writeln!(
                                output,
                                "   {}: {} requests remaining",
                                profile.profile_name, remaining
                            );
                        }
                    }
                }
            }
        }

        // Add metadata as JSON at the end of output for programmatic parsing
        let _ = write!(
            output,
            "\n\n<!-- metadata: {} -->",
            json!({
                "available_providers": available,
                "rate_limited_providers": rate_limited,
                "circuit_open_providers": circuit_open,
            })
        );

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

/// Tool for switching providers mid-conversation.
///
/// Allows agent to decide: "переключаюсь на gemini" when rate limited.
pub struct SwitchProviderTool;

#[async_trait]
impl Tool for SwitchProviderTool {
    fn name(&self) -> &str {
        "switch_provider"
    }

    fn description(&self) -> &str {
        "Switch to a different AI provider/model. Use when current provider is rate-limited \
         or when user explicitly requests a specific provider for a task. \
         Examples: 'use gemini for this', 'switch to anthropic'."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "provider": {
                    "type": "string",
                    "description": "Provider name (e.g., 'gemini', 'openai', 'anthropic')",
                },
                "model": {
                    "type": "string",
                    "description": "Specific model (optional, e.g., 'gemini-2.5-flash', 'claude-opus-4')"
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for switching (for logging and user notification)"
                }
            },
            "required": ["provider"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        let provider = args["provider"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing provider"))?;
        let model = args.get("model").and_then(|v| v.as_str());
        let reason = args
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("user request");

        // This tool sets metadata for the agent loop to pick up
        // The actual switching happens in agent/loop_.rs
        let output = format!(
            "🔄 Switching to {provider}{}. Reason: {reason}\n\n\
             <!-- metadata: {} -->",
            model.map(|m| format!(" (model: {m})")).unwrap_or_default(),
            json!({
                "action": "switch_provider",
                "provider": provider,
                "model": model,
                "reason": reason,
            })
        );

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

/// Tool for estimating quota cost before expensive operations.
///
/// Allows agent to predict: "это займет ~100 токенов"
pub struct EstimateQuotaCostTool;

#[async_trait]
impl Tool for EstimateQuotaCostTool {
    fn name(&self) -> &str {
        "estimate_quota_cost"
    }

    fn description(&self) -> &str {
        "Estimate quota cost (tokens, requests) for an operation before executing it. \
         Useful for warning user if operation may exhaust quota or when planning \
         parallel tool calls."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "description": "Operation type",
                    "enum": ["tool_call", "chat_response", "parallel_tools", "file_analysis"]
                },
                "estimated_tokens": {
                    "type": "integer",
                    "description": "Estimated input+output tokens (optional, default: 1000)"
                },
                "parallel_count": {
                    "type": "integer",
                    "description": "Number of parallel operations (if applicable, default: 1)"
                }
            },
            "required": ["operation"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult> {
        let operation = args["operation"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing operation"))?;
        let estimated_tokens = args
            .get("estimated_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(1000);
        let parallel_count = args
            .get("parallel_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        // Simple cost estimation (can be improved with provider-specific pricing)
        let total_tokens = estimated_tokens * parallel_count;
        let total_requests = parallel_count;

        // Rough cost estimate (based on average pricing)
        let cost_per_1k_tokens = 0.015; // Average across providers
        let estimated_cost_usd = (total_tokens as f64 / 1000.0) * cost_per_1k_tokens;

        let output = format!(
            "📊 Estimated cost for {operation}:\n\
             • Requests: {total_requests}\n\
             • Tokens: {total_tokens}\n\
             • Cost: ${estimated_cost_usd:.4} USD (estimate)\n\
             \n\
             Note: Actual cost may vary by provider and model."
        );

        Ok(ToolResult {
            success: true,
            output,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_provider_quota_schema() {
        let tool = CheckProviderQuotaTool::new(Arc::new(Config::default()));
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["provider"].is_object());
    }

    #[test]
    fn test_switch_provider_schema() {
        let tool = SwitchProviderTool;
        let schema = tool.parameters_schema();
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&json!("provider")));
    }

    #[test]
    fn test_estimate_quota_schema() {
        let tool = EstimateQuotaCostTool;
        let schema = tool.parameters_schema();
        assert!(schema["properties"]["operation"]["enum"].is_array());
    }
}
