use std::borrow::Cow;
use std::time::Duration;

use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::RoleClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::config::{ServerConfig, ServerHookConfig};

/// Outcome of running a subprocess hook on an MCP JSON-RPC message.
#[derive(Debug)]
pub enum HookOutcome {
    /// Proceed. If `Some(val)`, replace the message with this patched JSON-RPC message.
    Allow(Option<serde_json::Value>),
    /// Deny / Block. Outgoing requests are halted and a synthetic JSON-RPC error response is returned.
    Deny(String),
    /// Subprocess failed, timed out, or produced malformed output.
    Error(String),
}

/// Spawns the hook subprocess, pipes `payload` into `stdin`, and processes `stdout`/`stderr`/exit code.
pub async fn run_hook(
    hook: &ServerHookConfig,
    server: &ServerConfig,
    direction: &str,
    payload: &serde_json::Value,
) -> HookOutcome {
    let mut command = tokio::process::Command::new(&hook.command);
    command.args(&hook.args);
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    // Context environment variables
    command.env("PRISM_SERVER_ID", &server.id);
    command.env("PRISM_SERVER_NAME", &server.name);
    command.env("PRISM_DIRECTION", direction);
    if let Some(method) = payload.get("method").and_then(|m| m.as_str()) {
        command.env("PRISM_METHOD", method);
    }
    if let Some(id) = payload.get("id") {
        command.env("PRISM_MESSAGE_ID", id.to_string());
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return HookOutcome::Error(format!(
                "could not spawn server hook '{}': {}",
                hook.command, err
            ));
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let bytes = match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(err) => {
                return HookOutcome::Error(format!("could not serialize payload for hook: {}", err));
            }
        };
        if let Err(err) = stdin.write_all(&bytes).await {
            return HookOutcome::Error(format!("failed writing to hook stdin: {}", err));
        }
        drop(stdin);
    }

    let mut stdout = match child.stdout.take() {
        Some(s) => s,
        None => return HookOutcome::Error("failed to capture hook stdout".into()),
    };
    let mut stderr = match child.stderr.take() {
        Some(s) => s,
        None => return HookOutcome::Error("failed to capture hook stderr".into()),
    };
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();

    let timeout_dur = Duration::from_secs(hook.timeout_secs.max(1));
    let read_fut = async {
        tokio::try_join!(
            stdout.read_to_end(&mut stdout_bytes),
            stderr.read_to_end(&mut stderr_bytes),
            child.wait()
        )
    };

    let wait_res = tokio::time::timeout(timeout_dur, read_fut).await;

    let (_, _, status) = match wait_res {
        Ok(Ok(res)) => res,
        Ok(Err(err)) => {
            return HookOutcome::Error(format!("error waiting for hook: {}", err));
        }
        Err(_) => {
            let _ = child.kill().await;
            return HookOutcome::Error(format!(
                "server hook timed out after {}s",
                hook.timeout_secs
            ));
        }
    };

    match status.code() {
        Some(0) => {
            let stdout_str = String::from_utf8_lossy(&stdout_bytes);
            let trimmed = stdout_str.trim();
            if trimmed.is_empty() {
                HookOutcome::Allow(None)
            } else {
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(val) => HookOutcome::Allow(Some(val)),
                    Err(err) => HookOutcome::Error(format!(
                        "server hook produced invalid JSON stdout: {}",
                        err
                    )),
                }
            }
        }
        Some(2) => {
            let stderr_str = String::from_utf8_lossy(&stderr_bytes);
            let reason = if !stderr_str.trim().is_empty() {
                stderr_str.trim().to_string()
            } else {
                let stdout_str = String::from_utf8_lossy(&stdout_bytes);
                if !stdout_str.trim().is_empty() {
                    stdout_str.trim().to_string()
                } else {
                    "Denied by server hook".to_string()
                }
            };
            HookOutcome::Deny(reason)
        }
        Some(code) => {
            let stderr_str = String::from_utf8_lossy(&stderr_bytes);
            let msg = if !stderr_str.trim().is_empty() {
                stderr_str.trim().to_string()
            } else {
                format!("server hook exited with status code {}", code)
            };
            HookOutcome::Error(msg)
        }
        None => HookOutcome::Error("server hook terminated by signal".into()),
    }
}

/// A transport layer that intercepts raw MCP JSON-RPC messages between Prism and an upstream server.
pub struct ServerHookTransport<E> {
    outbound_tx: mpsc::Sender<TxJsonRpcMessage<RoleClient>>,
    inbound_rx: mpsc::Receiver<Option<RxJsonRpcMessage<RoleClient>>>,
    synthetic_rx: mpsc::UnboundedReceiver<RxJsonRpcMessage<RoleClient>>,
    synthetic_tx: mpsc::UnboundedSender<RxJsonRpcMessage<RoleClient>>,
    config: ServerConfig,
    hook: ServerHookConfig,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: std::error::Error + Send + Sync + 'static> ServerHookTransport<E> {
    pub fn new<T>(mut inner: T, config: ServerConfig, hook: ServerHookConfig) -> Self
    where
        T: Transport<RoleClient, Error = E> + 'static,
    {
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<TxJsonRpcMessage<RoleClient>>(32);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Option<RxJsonRpcMessage<RoleClient>>>(32);
        let (synthetic_tx, synthetic_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    Some(msg) = outbound_rx.recv() => {
                        if inner.send(msg).await.is_err() {
                            break;
                        }
                    }
                    item = inner.receive() => {
                        let is_none = item.is_none();
                        let _ = inbound_tx.send(item).await;
                        if is_none {
                            break;
                        }
                    }
                }
            }
            let _ = inner.close().await;
        });

        Self {
            outbound_tx,
            inbound_rx,
            synthetic_rx,
            synthetic_tx,
            config,
            hook,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E: std::error::Error + Send + Sync + 'static> Transport<RoleClient> for ServerHookTransport<E> {
    type Error = E;

    fn name() -> Cow<'static, str> {
        "server-hook".into()
    }

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
        let outbound_tx = self.outbound_tx.clone();
        let config = self.config.clone();
        let hook = self.hook.clone();
        let synthetic_tx = self.synthetic_tx.clone();

        async move {
            let intercept_send = hook.direction.intercepts_send();
            let payload = serde_json::to_value(&item).ok();

            if !intercept_send || payload.is_none() {
                let _ = outbound_tx.send(item).await;
                return Ok(());
            }

            let req_val = payload.unwrap();
            let outcome = run_hook(&hook, &config, "send", &req_val).await;
            match outcome {
                HookOutcome::Allow(None) => {
                    let _ = outbound_tx.send(item).await;
                    Ok(())
                }
                HookOutcome::Allow(Some(patched_val)) => {
                    match serde_json::from_value::<TxJsonRpcMessage<RoleClient>>(patched_val) {
                        Ok(patched_item) => {
                            debug!(server = %config.name, "patched outgoing MCP message");
                            let _ = outbound_tx.send(patched_item).await;
                        }
                        Err(err) => {
                            warn!(server = %config.name, error = %err, "could not deserialize patched JSON as TxJsonRpcMessage; using original");
                            let _ = outbound_tx.send(item).await;
                        }
                    }
                    Ok(())
                }
                HookOutcome::Deny(reason) => {
                    warn!(server = %config.name, reason = %reason, "server hook denied outgoing MCP message");
                    if let Some(id) = req_val.get("id").cloned() {
                        let err_response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32000,
                                "message": format!("Denied by server hook: {}", reason)
                            }
                        });
                        if let Ok(synthetic_msg) = serde_json::from_value::<RxJsonRpcMessage<RoleClient>>(err_response) {
                            let _ = synthetic_tx.send(synthetic_msg);
                        }
                    }
                    Ok(())
                }
                HookOutcome::Error(err_msg) => {
                    error!(server = %config.name, error = %err_msg, "server hook error on outgoing MCP message");
                    if let Some(id) = req_val.get("id").cloned() {
                        let err_response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32603,
                                "message": format!("Server hook error: {}", err_msg)
                            }
                        });
                        if let Ok(synthetic_msg) = serde_json::from_value::<RxJsonRpcMessage<RoleClient>>(err_response) {
                            let _ = synthetic_tx.send(synthetic_msg);
                        }
                    }
                    Ok(())
                }
            }
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
        if let Ok(msg) = self.synthetic_rx.try_recv() {
            return Some(msg);
        }

        let raw_item = tokio::select! {
            Some(synth) = self.synthetic_rx.recv() => return Some(synth),
            item = self.inbound_rx.recv() => item??,
        };

        if !self.hook.direction.intercepts_recv() {
            return Some(raw_item);
        }

        let payload = match serde_json::to_value(&raw_item).ok() {
            Some(v) => v,
            None => return Some(raw_item),
        };

        let outcome = run_hook(&self.hook, &self.config, "recv", &payload).await;
        match outcome {
            HookOutcome::Allow(None) => Some(raw_item),
            HookOutcome::Allow(Some(patched_val)) => {
                match serde_json::from_value::<RxJsonRpcMessage<RoleClient>>(patched_val) {
                    Ok(patched_item) => {
                        debug!(server = %self.config.name, "patched incoming MCP message");
                        Some(patched_item)
                    }
                    Err(err) => {
                        warn!(server = %self.config.name, error = %err, "could not deserialize patched JSON as RxJsonRpcMessage; using original");
                        Some(raw_item)
                    }
                }
            }
            HookOutcome::Deny(reason) => {
                warn!(server = %self.config.name, reason = %reason, "server hook denied incoming MCP message");
                if let Some(id) = payload.get("id").cloned() {
                    let err_response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32000,
                            "message": format!("Denied by server hook: {}", reason)
                        }
                    });
                    if let Ok(synthetic_msg) = serde_json::from_value::<RxJsonRpcMessage<RoleClient>>(err_response) {
                        return Some(synthetic_msg);
                    }
                }
                Some(raw_item)
            }
            HookOutcome::Error(err_msg) => {
                error!(server = %self.config.name, error = %err_msg, "server hook error on incoming MCP message");
                Some(raw_item)
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use super::*;
    use crate::config::HookDirection;

    fn test_server() -> ServerConfig {
        ServerConfig {
            id: "test-srv".into(),
            name: "test-server".into(),
            command: "echo".into(),
            args: Vec::new(),
            env: Default::default(),
            credential_ref: None,
            enabled: true,
            url: None,
            auth: crate::config::HttpAuth::None,
            headers: Default::default(),
            oauth_ref: None,
            hidden_tools: Default::default(),
            hook: None,
        }
    }

    #[tokio::test]
    async fn run_hook_allows_with_empty_stdout() {
        let server = test_server();
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), "import sys; sys.exit(0)".into()],
            direction: HookDirection::Send,
            timeout_secs: 5,
        };
        let payload = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let outcome = run_hook(&hook, &server, "send", &payload).await;
        assert!(matches!(outcome, HookOutcome::Allow(None)));
    }

    #[tokio::test]
    async fn run_hook_patches_json_on_exit_zero() {
        let server = test_server();
        let script = r#"
import sys, json
data = json.load(sys.stdin)
data["params"] = {"patched": True}
json.dump(data, sys.stdout)
"#;
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), script.into()],
            direction: HookDirection::Send,
            timeout_secs: 5,
        };
        let payload = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"patched": false}});
        let outcome = run_hook(&hook, &server, "send", &payload).await;
        match outcome {
            HookOutcome::Allow(Some(val)) => {
                assert_eq!(val["params"]["patched"], true);
            }
            other => panic!("expected Allow(Some(_)), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn run_hook_denies_on_exit_two() {
        let server = test_server();
        let script = r#"
import sys
sys.stderr.write("access denied for secret parameter\n")
sys.exit(2)
"#;
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), script.into()],
            direction: HookDirection::Send,
            timeout_secs: 5,
        };
        let payload = serde_json::json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call"});
        let outcome = run_hook(&hook, &server, "send", &payload).await;
        match outcome {
            HookOutcome::Deny(reason) => {
                assert_eq!(reason, "access denied for secret parameter");
            }
            other => panic!("expected Deny, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn run_hook_times_out() {
        let server = test_server();
        let script = "import time; time.sleep(10)";
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), script.into()],
            direction: HookDirection::Send,
            timeout_secs: 1,
        };
        let payload = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        let outcome = run_hook(&hook, &server, "send", &payload).await;
        match outcome {
            HookOutcome::Error(err) => {
                assert!(err.contains("timed out"));
            }
            other => panic!("expected Error with timeout, got {:?}", other),
        }
    }

    struct MockTransport {
        sent: Arc<tokio::sync::Mutex<Vec<TxJsonRpcMessage<RoleClient>>>>,
        recv_rx: mpsc::Receiver<RxJsonRpcMessage<RoleClient>>,
    }

    impl MockTransport {
        fn new() -> (Self, Arc<tokio::sync::Mutex<Vec<TxJsonRpcMessage<RoleClient>>>>, mpsc::Sender<RxJsonRpcMessage<RoleClient>>) {
            let sent = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let (tx, rx) = mpsc::channel(16);
            (
                Self {
                    sent: sent.clone(),
                    recv_rx: rx,
                },
                sent,
                tx,
            )
        }
    }

    impl Transport<RoleClient> for MockTransport {
        type Error = std::io::Error;

        fn name() -> Cow<'static, str> {
            "mock".into()
        }

        fn send(
            &mut self,
            item: TxJsonRpcMessage<RoleClient>,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let sent = self.sent.clone();
            async move {
                sent.lock().await.push(item);
                Ok(())
            }
        }

        async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
            self.recv_rx.recv().await
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn hook_transport_denies_outgoing_and_synthesizes_error_response() {
        let server = test_server();
        let script = r#"
import sys
sys.stderr.write("unauthorized call to secret tool\n")
sys.exit(2)
"#;
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), script.into()],
            direction: HookDirection::Send,
            timeout_secs: 5,
        };

        let (mock, sent, _recv_tx) = MockTransport::new();
        let mut transport = ServerHookTransport::new(mock, server, hook);

        let req_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "secret"}
        });
        let req_msg: TxJsonRpcMessage<RoleClient> = serde_json::from_value(req_json).unwrap();

        transport.send(req_msg).await.unwrap();

        // 1. Upstream transport should NOT have received the message!
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(sent.lock().await.is_empty());

        // 2. Synthetic response queue should immediately return a JSON-RPC error response!
        let response = transport.receive().await.expect("expected synthetic response");
        let resp_val = serde_json::to_value(&response).unwrap();

        assert_eq!(resp_val["id"], 99);
        assert!(resp_val["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Denied by server hook: unauthorized call to secret tool"));
    }

    #[tokio::test]
    async fn hook_transport_patches_outgoing_request() {
        let server = test_server();
        let script = r#"
import sys, json
msg = json.load(sys.stdin)
msg["params"]["arguments"]["path"] = "/patched/file.txt"
json.dump(msg, sys.stdout)
"#;
        let hook = ServerHookConfig {
            command: "python3".into(),
            args: vec!["-c".into(), script.into()],
            direction: HookDirection::Send,
            timeout_secs: 5,
        };

        let (mock, sent, _recv_tx) = MockTransport::new();
        let mut transport = ServerHookTransport::new(mock, server, hook);

        let req_json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/original/file.txt"
                }
            }
        });
        let req_msg: TxJsonRpcMessage<RoleClient> = serde_json::from_value(req_json).unwrap();

        transport.send(req_msg).await.unwrap();

        // Upstream transport should receive the PATCHED message!
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sent_msgs = sent.lock().await;
        assert_eq!(sent_msgs.len(), 1);
        let sent_val = serde_json::to_value(&sent_msgs[0]).unwrap();
        assert_eq!(
            sent_val["params"]["arguments"]["path"],
            "/patched/file.txt"
        );
    }
}
