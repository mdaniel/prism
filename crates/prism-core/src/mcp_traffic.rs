use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use axum::extract::State;

/// A recorded MCP JSON-RPC message or completed transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpTransaction {
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "type")]
    pub kind: String, // "transaction" | "notification"
    pub agent_id: String,
    pub agent_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Uncapped, persistent append-only logger for all MCP JSON-RPC traffic.
#[derive(Clone)]
pub struct McpTrafficLogger {
    path: PathBuf,
    writer: Arc<Mutex<Option<File>>>,
}

impl McpTrafficLogger {
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(Some(file))),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, transaction: McpTransaction) {
        let line = match serde_json::to_string(&transaction) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(%err, "failed to serialize MCP transaction");
                return;
            }
        };

        let mut lock = self.writer.lock().expect("mcp traffic writer poisoned");
        if lock.is_none() {
            match OpenOptions::new().create(true).append(true).open(&self.path) {
                Ok(file) => *lock = Some(file),
                Err(err) => {
                    tracing::error!(%err, "failed to reopen mcp traffic log");
                    return;
                }
            }
        }

        if let Some(file) = lock.as_mut() {
            if let Err(err) = writeln!(file, "{line}").and_then(|_| file.flush()) {
                tracing::error!(%err, "failed to write mcp traffic log");
            }
        }
    }
}

#[allow(dead_code)]
pub(crate) async fn log_traffic(
    State(gateway): State<Arc<crate::gateway::Gateway>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::body::{to_bytes, Body};

    let session_id = req
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let auth_agent = req.extensions().get::<crate::oauth::AuthenticatedAgent>().cloned();
    let agent_id = auth_agent.map(|a| a.agent_id).unwrap_or_else(|| "unknown".into());
    let agent_name = gateway
        .agent_by_id(&agent_id)
        .await
        .map(|a| a.name)
        .unwrap_or_else(|| agent_id.clone());

    let (parts, body) = req.into_parts();
    let http_method = parts.method.clone();
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return next.run(axum::extract::Request::from_parts(parts, Body::empty())).await,
    };

    let req_json: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
    let req = axum::extract::Request::from_parts(parts, Body::from(bytes));

    let started = std::time::Instant::now();
    let response = next.run(req).await;
    let duration_ms = started.elapsed().as_millis() as u64;

    let is_sse = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));

    let (res_parts, res_body) = response.into_parts();

    if is_sse && http_method == http::Method::GET {
        // Long-lived GET SSE stream: do not buffer response body.
        return axum::response::Response::from_parts(res_parts, res_body);
    }

    let res_bytes = match to_bytes(res_body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return axum::response::Response::from_parts(res_parts, Body::empty()),
    };

    let res_json: Option<serde_json::Value> = if is_sse {
        std::str::from_utf8(&res_bytes).ok().and_then(|text| {
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("data:") {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(rest.trim()) {
                        return Some(val);
                    }
                }
            }
            None
        })
    } else {
        serde_json::from_slice(&res_bytes).ok()
    };

    let response = axum::response::Response::from_parts(res_parts, Body::from(res_bytes));

    if let Some(req_val) = req_json {
        let (method, id, params, is_notification) = match req_val {
            serde_json::Value::Object(ref map) => {
                let m = map.get("method").and_then(|m| m.as_str()).unwrap_or("unknown").to_string();
                let i = map.get("id").cloned();
                let p = map.get("params").cloned();
                let notif = i.is_none() || i.as_ref().is_some_and(|v| v.is_null());
                (m, i, p, notif)
            }
            _ => ("unknown".to_string(), None, None, false),
        };

        let (resp_payload, error_str) = if let Some(ref res_val) = res_json {
            if let Some(err_val) = res_val.get("error") {
                let err_msg = err_val
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| err_val.to_string());
                (Some(err_val.clone()), Some(err_msg))
            } else {
                (res_val.get("result").cloned(), None)
            }
        } else {
            (None, None)
        };

        gateway.mcp_traffic.record(McpTransaction {
            timestamp: Utc::now(),
            kind: if is_notification { "notification".into() } else { "transaction".into() },
            agent_id,
            agent_name,
            session_id,
            id,
            method,
            request: params,
            response: resp_payload,
            duration_ms: Some(duration_ms),
            error: error_str,
        });
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn records_transactions_and_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.jsonl");
        let logger = McpTrafficLogger::new(&path).unwrap();

        let t1 = McpTransaction {
            timestamp: Utc::now(),
            kind: "transaction".into(),
            agent_id: "claude-code".into(),
            agent_name: "Claude Code".into(),
            session_id: Some("sess-1".into()),
            id: Some(json!(1)),
            method: "tools/call".into(),
            request: Some(json!({"name": "filesystem__read_file", "arguments": {"path": "/foo"}})),
            response: Some(json!({"content": [{"type": "text", "text": "bar"}]})),
            duration_ms: Some(25),
            error: None,
        };

        let t2 = McpTransaction {
            timestamp: Utc::now(),
            kind: "notification".into(),
            agent_id: "claude-code".into(),
            agent_name: "Claude Code".into(),
            session_id: Some("sess-1".into()),
            id: None,
            method: "notifications/tools/list_changed".into(),
            request: None,
            response: None,
            duration_ms: None,
            error: None,
        };

        logger.record(t1.clone());
        logger.record(t2.clone());

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: McpTransaction = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed1.method, "tools/call");
        assert_eq!(parsed1.request, t1.request);
        assert_eq!(parsed1.response, t1.response);
        assert_eq!(parsed1.duration_ms, Some(25));

        let parsed2: McpTransaction = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(parsed2.method, "notifications/tools/list_changed");
        assert_eq!(parsed2.kind, "notification");
    }
}
