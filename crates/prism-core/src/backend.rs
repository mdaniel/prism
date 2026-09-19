use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ProtocolVersion, SubscriptionFilter, Tool,
};
use rmcp::service::{NotificationContext, Peer, RunningService};
use rmcp::transport::TokioChildProcess;
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::ServerConfig;
use crate::error::{Error, Result};
use crate::events::{EventSender, GatewayEvent};

const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime status of one spawned MCP backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendStatus {
    Starting,
    Running { tool_count: usize },
    Failed { error: String },
    Stopped,
    SignInRequired,
}

/// Legacy notifications are coalesced before doing any network work.
#[derive(Default, Clone)]
pub(crate) struct Upstream {
    changed: Arc<Notify>,
}

impl ClientHandler for Upstream {
    async fn on_tool_list_changed(&self, context: NotificationContext<RoleClient>) {
        if supports_updates(&context.peer) {
            self.changed.notify_one();
        }
    }
}

pub(crate) type McpClient = RunningService<RoleClient, Upstream>;

struct Backend {
    config: ServerConfig,
    status: BackendStatus,
    client: Option<Arc<McpClient>>,
    tools: Vec<Tool>,
    refresh: Arc<Mutex<()>>,
    generation: uuid::Uuid,
    stop: CancellationToken,
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(client) = &self.client {
            client.cancellation_token().cancel();
        }
    }
}

#[derive(Default)]
struct Catalog {
    entries: HashMap<String, Backend>,
    // None means two configured server/tool pairs have the same public name.
    routes: HashMap<String, Option<(String, usize)>>,
}

impl Catalog {
    /// Called only when a catalog changes, never on the tool-call path.
    fn reindex(&mut self) {
        self.routes.clear();
        for (id, backend) in &self.entries {
            if !matches!(backend.status, BackendStatus::Running { .. }) {
                continue;
            }
            for (index, tool) in backend.tools.iter().enumerate() {
                let name = format!("{}__{}", backend.config.name, tool.name);
                self.routes
                    .entry(name)
                    .and_modify(|route| *route = None)
                    .or_insert_with(|| Some((id.clone(), index)));
            }
        }
    }
}

/// Owns backend lifetimes and an atomically published tool catalog.
pub struct BackendManager {
    backends: Arc<RwLock<Catalog>>,
    events: EventSender,
    credentials: Arc<dyn crate::credentials::CredentialStore>,
    traffic: Arc<crate::mcp_traffic::McpTrafficLogger>,
}

impl BackendManager {
    #[allow(dead_code)]
    pub(crate) fn new(
        events: EventSender,
        credentials: Arc<dyn crate::credentials::CredentialStore>,
    ) -> Self {
        Self::with_traffic(
            events,
            credentials,
            Arc::new(crate::mcp_traffic::McpTrafficLogger::ephemeral()),
        )
    }

    pub(crate) fn with_traffic(
        events: EventSender,
        credentials: Arc<dyn crate::credentials::CredentialStore>,
        traffic: Arc<crate::mcp_traffic::McpTrafficLogger>,
    ) -> Self {
        Self {
            backends: Arc::new(RwLock::new(Catalog::default())),
            events,
            credentials,
            traffic,
        }
    }

    pub async fn start(&self, config: ServerConfig) {
        let id = config.id.clone();
        let generation = uuid::Uuid::new_v4();
        let stop = CancellationToken::new();
        let status = if config.enabled {
            BackendStatus::Starting
        } else {
            BackendStatus::Stopped
        };
        {
            let mut catalog = self.backends.write().await;
            catalog.entries.insert(
                id.clone(),
                Backend {
                    config: config.clone(),
                    status: status.clone(),
                    client: None,
                    tools: Vec::new(),
                    refresh: Default::default(),
                    generation,
                    stop: stop.clone(),
                },
            );
            catalog.reindex();
        }
        self.status(&id, status);
        if !config.enabled {
            return;
        }
        let connected = tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            result = connect(&config, self.credentials.clone(), self.traffic.clone()) => result,
        };
        let mut catalog = self.backends.write().await;
        let Some(backend) = catalog
            .entries
            .get_mut(&id)
            .filter(|backend| backend.generation == generation && !backend.stop.is_cancelled())
        else {
            return;
        };
        match connected {
            Ok((client, tools)) => {
                let peer = client.peer().clone();
                let changes = client.service().changed.clone();
                let status = BackendStatus::Running {
                    tool_count: tools.len(),
                };
                info!(server = %config.name, tool_count = tools.len(), "backend running");
                backend.status = status.clone();
                backend.client = Some(Arc::new(client));
                backend.tools = tools;
                catalog.reindex();
                self.status(&id, status);
                if supports_updates(&peer) {
                    tokio::spawn(watch_tools(
                        Arc::downgrade(&self.backends),
                        self.events.clone(),
                        id,
                        generation,
                        peer,
                        changes,
                        stop,
                    ));
                }
            }
            Err(err) => {
                let status = match err {
                    Error::SignInRequired => BackendStatus::SignInRequired,
                    err => BackendStatus::Failed {
                        error: err.to_string(),
                    },
                };
                backend.status = status.clone();
                catalog.reindex();
                self.status(&id, status);
            }
        }
    }

    fn status(&self, server_id: &str, status: BackendStatus) {
        let _ = self.events.send(GatewayEvent::ServerStatus {
            server_id: server_id.to_string(),
            status,
        });
    }

    pub async fn stop(&self, server_id: &str) {
        let client = {
            let mut catalog = self.backends.write().await;
            let Some(backend) = catalog.entries.get_mut(server_id) else {
                return;
            };
            backend.stop.cancel();
            backend.generation = uuid::Uuid::new_v4();
            let client = backend.client.take();
            backend.tools.clear();
            backend.status = BackendStatus::Stopped;
            catalog.reindex();
            self.status(server_id, BackendStatus::Stopped);
            client
        };
        // A stalled peer must not hold the catalog lock for other servers.
        if let Some(client) = client {
            client.cancellation_token().cancel();
            if let Ok(mut client) = Arc::try_unwrap(client) {
                if client
                    .close_with_timeout(Duration::from_secs(3))
                    .await
                    .is_err()
                {
                    warn!(
                        server_id,
                        "backend close failed; details omitted to protect credentials"
                    );
                }
            }
        }
    }

    pub async fn remove(&self, server_id: &str) {
        self.stop(server_id).await;
        let mut catalog = self.backends.write().await;
        catalog.entries.remove(server_id);
        catalog.reindex();
    }

    pub async fn mark_failed(&self, server_id: &str, error: String) {
        let mut catalog = self.backends.write().await;
        if let Some(backend) = catalog.entries.get_mut(server_id) {
            backend.stop.cancel();
            if let Some(client) = &backend.client {
                client.cancellation_token().cancel();
            }
            backend.client = None;
            backend.tools.clear();
            backend.status = BackendStatus::Failed { error };
            self.status(server_id, backend.status.clone());
            catalog.reindex();
        }
    }

    pub async fn restart(&self, server_id: &str) -> Result<()> {
        let config = self
            .backends
            .read()
            .await
            .entries
            .get(server_id)
            .map(|backend| backend.config.clone())
            .ok_or_else(|| Error::NotFound(format!("server {server_id}")))?;
        self.stop(server_id).await;
        self.start(config).await;
        Ok(())
    }

    pub async fn list_tools(&self, refresh: bool) -> Vec<(ServerConfig, Tool)> {
        if refresh {
            self.refresh_all().await;
        }
        let catalog = self.backends.read().await;
        let mut tools: Vec<_> = catalog
            .routes
            .values()
            .filter_map(|route| {
                let (id, index) = route.as_ref()?;
                let backend = catalog.entries.get(id)?;
                Some((backend.config.clone(), backend.tools[*index].clone()))
            })
            .collect();
        // Routes live in a hash map; give the panel and agents one stable order.
        tools.sort_by(|(a, x), (b, y)| a.name.cmp(&b.name).then_with(|| x.name.cmp(&y.name)));
        tools
    }

    /// Resolve the exact advertised name and its annotations in one lookup.
    pub async fn resolve_tool(&self, name: &str) -> Option<(ServerConfig, Tool)> {
        let catalog = self.backends.read().await;
        let (id, index) = catalog.routes.get(name)?.as_ref()?;
        let backend = catalog.entries.get(id)?;
        Some((backend.config.clone(), backend.tools[*index].clone()))
    }

    pub async fn call_tool(
        &self,
        server_id: &str,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<CallToolResult> {
        let client = {
            let catalog = self.backends.read().await;
            let backend = catalog
                .entries
                .get(server_id)
                .ok_or_else(|| Error::NotFound(format!("server {server_id}")))?;
            backend
                .client
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::Backend(format!("server {server_id} is not running")))?
        };
        client
            .call_tool(call_params(name, arguments))
            .await
            .map_err(|err| {
                tracing::warn!(server = server_id, tool = name, error = %err, "backend tool call failed");
                Error::Backend(format!("tool call failed: {err}"))
            })
    }

    pub async fn snapshot(&self) -> Vec<(ServerConfig, BackendStatus)> {
        self.backends
            .read()
            .await
            .entries
            .values()
            .map(|backend| (backend.config.clone(), backend.status.clone()))
            .collect()
    }

    pub async fn running_count(&self) -> usize {
        self.backends
            .read()
            .await
            .entries
            .values()
            .filter(|backend| matches!(backend.status, BackendStatus::Running { .. }))
            .count()
    }

    async fn refresh_all(&self) {
        let peers: Vec<_> = self
            .backends
            .read()
            .await
            .entries
            .iter()
            .filter_map(|(id, backend)| {
                Some((
                    id.clone(),
                    backend.generation,
                    backend.client.as_ref()?.peer().clone(),
                ))
            })
            .collect();
        let mut refreshes = tokio::task::JoinSet::new();
        for (id, generation, peer) in peers {
            let catalog = Arc::downgrade(&self.backends);
            let events = self.events.clone();
            refreshes.spawn(async move {
                if refresh_tools(&catalog, &events, &id, generation, &peer)
                    .await
                    .is_err()
                {
                    warn!(server_id = %id, "tool refresh failed; keeping last known catalog");
                }
            });
        }
        while refreshes.join_next().await.is_some() {}
    }
}

fn supports_updates(peer: &Peer<RoleClient>) -> bool {
    peer.peer_info().is_some_and(|info| {
        info.capabilities
            .tools
            .as_ref()
            .is_some_and(|tools| tools.list_changed == Some(true))
    })
}

async fn list_peer_tools(peer: &Peer<RoleClient>) -> Result<Vec<Tool>> {
    let mut tools = tokio::time::timeout(REFRESH_TIMEOUT, peer.list_all_tools())
        .await
        .map_err(|err| Error::Backend(format!("tool listing timed out: {err}")))?
        .map_err(|err| {
            Error::Backend(format!(
                "tool listing failed: {err}"
            ))
        })?;
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(tools)
}

#[cfg(test)]
#[path = "backend_updates_tests.rs"]
mod updates_tests;

async fn refresh_tools(
    catalog: &Weak<RwLock<Catalog>>,
    events: &EventSender,
    id: &str,
    generation: uuid::Uuid,
    peer: &Peer<RoleClient>,
) -> Result<()> {
    let Some(shared) = catalog.upgrade() else {
        return Ok(());
    };
    let (refresh, stop) = {
        let catalog = shared.read().await;
        let Some(backend) = catalog
            .entries
            .get(id)
            .filter(|backend| backend.generation == generation)
        else {
            return Ok(());
        };
        (backend.refresh.clone(), backend.stop.clone())
    };
    drop(shared);
    // Serialize explicit refreshes with notifications for this server only.
    // A slow older response must never overwrite a newer catalog.
    let _guard = tokio::select! {
        biased;
        _ = stop.cancelled() => return Ok(()),
        guard = refresh.lock() => guard,
    };
    let tools = list_peer_tools(peer).await?;
    let Some(catalog) = catalog.upgrade() else {
        return Ok(());
    };
    let mut catalog = catalog.write().await;
    let Some(backend) = catalog
        .entries
        .get_mut(id)
        .filter(|backend| backend.generation == generation && !backend.stop.is_cancelled())
    else {
        return Ok(());
    };
    if backend.tools != tools {
        backend.status = BackendStatus::Running {
            tool_count: tools.len(),
        };
        backend.tools = tools;
        let status = backend.status.clone();
        catalog.reindex();
        let _ = events.send(GatewayEvent::ServerStatus {
            server_id: id.to_string(),
            status,
        });
    }
    Ok(())
}

async fn watch_tools(
    catalog: Weak<RwLock<Catalog>>,
    events: EventSender,
    id: String,
    generation: uuid::Uuid,
    peer: Peer<RoleClient>,
    changes: Arc<Notify>,
    stop: CancellationToken,
) {
    // Dropping this future cancels an open subscription and any pending refresh.
    let work = async {
        let modern = peer
            .peer_info()
            .is_some_and(|info| info.protocol_version >= ProtocolVersion::V_2026_07_28);
        let mut retry = Duration::from_secs(1);
        loop {
            if peer.is_transport_closed() {
                break;
            }
            if modern {
                let listen = tokio::time::timeout(
                    REFRESH_TIMEOUT,
                    peer.listen(SubscriptionFilter::builder().tools_list_changed().build()),
                )
                .await;
                if let Ok(Ok(mut subscription)) = listen {
                    if subscription.acknowledged().tools_list_changed != Some(true) {
                        warn!(server_id = %id, "upstream declined tool updates; reconnect to refresh");
                        break;
                    }
                    // Refresh after acknowledgment to cover the initial list/subscribe gap.
                    loop {
                        if refresh_tools(&catalog, &events, &id, generation, &peer)
                            .await
                            .is_err()
                        {
                            warn!(server_id = %id, "tool refresh failed; retrying with last known catalog");
                            tokio::time::sleep(retry).await;
                            retry = (retry * 2).min(Duration::from_secs(30));
                            continue;
                        }
                        retry = Duration::from_secs(1);
                        match subscription.next().await {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                }
                // Re-establish an interrupted subscription without a tight reconnect loop.
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(Duration::from_secs(30));
            } else {
                changes.notified().await;
                loop {
                    if refresh_tools(&catalog, &events, &id, generation, &peer)
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    warn!(server_id = %id, "tool refresh failed; retrying with last known catalog");
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(Duration::from_secs(30));
                }
                retry = Duration::from_secs(1);
            }
        }
    };
    tokio::select! {
        biased;
        _ = stop.cancelled() => {},
        _ = work => {},
    }
}

async fn connect(
    config: &ServerConfig,
    store: Arc<dyn crate::credentials::CredentialStore>,
    traffic: Arc<crate::mcp_traffic::McpTrafficLogger>,
) -> Result<(McpClient, Vec<Tool>)> {
    let protected = config.clone();
    let blocking_store = store.clone();
    let launch = tokio::task::spawn_blocking(move || {
        crate::credentials::resolve(blocking_store.as_ref(), &protected)
    })
    .await
    .map_err(|_| Error::Backend("could not retrieve server credentials".into()))??;
    let client = if config.is_remote() {
        crate::remote::connect(config, &launch, store, traffic.clone()).await?
    } else {
        let mut command = server_command(config, &launch, std::env::vars_os());
        command.kill_on_drop(true);
        // Set this on the transport builder: its defaults override Command stdio settings.
        let (transport, stderr_opt) = TokioChildProcess::builder(command)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|err| {
                Error::Backend(format!(
                    "could not spawn server ({:?}); check its executable",
                    err.kind()
                ))
            })?;

        let stderr_lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        if let Some(err_reader) = stderr_opt {
            let buffer = stderr_lines.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let reader = tokio::io::BufReader::new(err_reader);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let mut b = buffer.lock().unwrap();
                    if b.len() < 50 {
                        b.push(line);
                    }
                }
            });
        }

        let serve_res = if let Some(ref hook) = config.hook {
            let hooked = crate::hook_transport::ServerHookTransport::new(
                transport,
                config.clone(),
                hook.clone(),
            );
            let logged = crate::mcp_traffic::ServerLoggingTransport::new(
                hooked,
                config.id.clone(),
                traffic.clone(),
            );
            tokio::time::timeout(REFRESH_TIMEOUT, Upstream::default().serve(logged)).await
        } else {
            let logged = crate::mcp_traffic::ServerLoggingTransport::new(
                transport,
                config.id.clone(),
                traffic.clone(),
            );
            tokio::time::timeout(REFRESH_TIMEOUT, Upstream::default().serve(logged)).await
        };

        match serve_res {
            Ok(Ok(client)) => client,
            Ok(Err(err)) => {
                let stderr_summary = {
                    let b = stderr_lines.lock().unwrap();
                    if b.is_empty() {
                        None
                    } else {
                        Some(b.join("\n"))
                    }
                };
                let msg = match stderr_summary {
                    Some(stderr) => format!("server handshake failed: {err}; stderr:\n{stderr}"),
                    None => format!("server handshake failed: {err}"),
                };
                traffic.record(crate::mcp_traffic::McpTransaction {
                    timestamp: chrono::Utc::now(),
                    kind: "handshake_failed".into(),
                    agent_id: config.id.clone(),
                    agent_name: config.name.clone(),
                    session_id: None,
                    id: None,
                    method: "handshake".into(),
                    request: None,
                    response: None,
                    duration_ms: None,
                    error: Some(msg.clone()),
                });
                return Err(Error::Backend(msg));
            }
            Err(_) => {
                let stderr_summary = {
                    let b = stderr_lines.lock().unwrap();
                    if b.is_empty() {
                        None
                    } else {
                        Some(b.join("\n"))
                    }
                };
                let msg = match stderr_summary {
                    Some(stderr) => format!("server handshake timed out; stderr:\n{stderr}"),
                    None => "server handshake timed out".to_string(),
                };
                traffic.record(crate::mcp_traffic::McpTransaction {
                    timestamp: chrono::Utc::now(),
                    kind: "handshake_failed".into(),
                    agent_id: config.id.clone(),
                    agent_name: config.name.clone(),
                    session_id: None,
                    id: None,
                    method: "handshake".into(),
                    request: None,
                    response: None,
                    duration_ms: None,
                    error: Some(msg.clone()),
                });
                return Err(Error::Backend(msg));
            }
        }
    };
    let tools = list_peer_tools(client.peer()).await?;
    Ok((client, tools))
}

fn inherited_env_allowed(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    #[cfg(windows)]
    let name = name.to_ascii_uppercase();
    #[cfg(windows)]
    let name = name.as_str();
    let common = matches!(
        name,
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "TZ"
            | "TMPDIR"
            | "TMP"
            | "TEMP"
            | "XDG_CACHE_HOME"
            | "XDG_CONFIG_HOME"
            | "XDG_DATA_HOME"
            | "UV_CACHE_DIR"
            | "NPM_CONFIG_CACHE"
            | "npm_config_cache"
    );
    #[cfg(windows)]
    let platform = matches!(
        name,
        "SYSTEMROOT"
            | "WINDIR"
            | "COMSPEC"
            | "PATHEXT"
            | "USERPROFILE"
            | "USERNAME"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "APPDATA"
            | "LOCALAPPDATA"
    );
    #[cfg(target_os = "linux")]
    let platform = matches!(
        name,
        "DISPLAY" | "WAYLAND_DISPLAY" | "XAUTHORITY" | "XDG_RUNTIME_DIR"
    );
    #[cfg(not(any(windows, target_os = "linux")))]
    let platform = false;
    common || platform
}

fn server_command(
    config: &ServerConfig,
    launch: &crate::credentials::LaunchSettings,
    parent: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Command {
    let mut command = Command::new(&config.command);
    command.env_clear();
    command.envs(
        parent
            .into_iter()
            .filter(|(name, _)| inherited_env_allowed(name)),
    );
    command.envs(&launch.env);
    command.args(&launch.args);
    command
}

fn call_params(name: &str, arguments: serde_json::Value) -> CallToolRequestParams {
    let params = CallToolRequestParams::new(name.to_string());
    match arguments {
        serde_json::Value::Object(map) => params.with_arguments(map),
        serde_json::Value::Null => params,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("value".into(), other);
            params.with_arguments(map)
        }
    }
}

/// Snapshot of a configured server plus its live status, for the desktop UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
    pub credentials_stored: bool,
    pub enabled: bool,
    pub status: BackendStatus,
    /// Endpoint of a remote server; `None` for a stdio one.
    pub url: Option<String>,
    pub auth: crate::config::HttpAuth,
    /// Tools the panel hid from every agent, by name.
    pub hidden_tools: Vec<String>,
    /// Subprocess hook configuration, if any.
    pub hook: Option<crate::config::ServerHookConfig>,
}

impl ServerView {
    pub fn from_parts(config: ServerConfig, status: BackendStatus) -> Self {
        Self {
            id: config.id,
            name: config.name,
            command: config.command,
            args: Vec::new(),
            env: Default::default(),
            credentials_stored: config.credential_ref.is_some(),
            enabled: config.enabled,
            status,
            url: config.url,
            auth: config.auth,
            hidden_tools: config.hidden_tools.into_iter().collect(),
            hook: config.hook,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::credentials::{protect_server, tests::MemoryStore};

    #[tokio::test]
    async fn child_receives_only_allowlisted_and_explicit_environment() {
        let config = ServerConfig {
            id: "env-test".into(),
            name: "env-test".into(),
            command: "python3".into(),
            args: vec![],
            env: Default::default(),
            enabled: true,
            credential_ref: None,
            url: None,
            auth: crate::config::HttpAuth::None,
            headers: Default::default(),
            oauth_ref: None,
            hidden_tools: Default::default(),
            hook: None,
        };
        let launch = crate::credentials::LaunchSettings {
            args: vec![
                "-c".into(),
                "import json,os; print(json.dumps(dict(os.environ)))".into(),
            ],
            env: std::collections::BTreeMap::from([
                ("HOME".into(), "/explicit/home".into()),
                ("CUSTOM_SERVER_TOKEN".into(), "explicit-secret".into()),
            ]),
            headers: Default::default(),
        };
        let parent = vec![
            ("PATH".into(), std::env::var_os("PATH").unwrap()),
            ("HOME".into(), "/inherited/home".into()),
            ("UV_CACHE_DIR".into(), "/cache/uv".into()),
            ("PRISM_UNRELATED_SECRET".into(), "must-not-leak".into()),
            ("NPM_CONFIG_TOKEN".into(), "must-not-leak".into()),
        ];
        let output = server_command(&config, &launch, parent)
            .output()
            .await
            .unwrap();
        assert!(output.status.success());
        let env: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(env["HOME"], "/explicit/home");
        assert_eq!(env["CUSTOM_SERVER_TOKEN"], "explicit-secret");
        assert_eq!(env["UV_CACHE_DIR"], "/cache/uv");
        assert!(env.get("PRISM_UNRELATED_SECRET").is_none());
        assert!(env.get("NPM_CONFIG_TOKEN").is_none());
    }

    #[tokio::test]
    #[ignore = "manually checks a configured server using the native credential store"]
    async fn configured_server_lists_tools() {
        let path = std::env::var_os("PRISM_TEST_CONFIG").expect("PRISM_TEST_CONFIG is required");
        // Read-only: do not migrate or rewrite the running desktop application's config.
        let config: crate::config::PrismConfig =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let name = std::env::var("PRISM_TEST_SERVER").unwrap_or_else(|_| "filesystem".into());
        let server = config
            .servers
            .iter()
            .find(|server| server.name == name)
            .expect("test server configured");
        let (mut client, tools) = tokio::time::timeout(
            Duration::from_secs(60),
            connect(
                server,
                Arc::new(crate::credentials::NativeStore::default()),
                Arc::new(crate::mcp_traffic::McpTrafficLogger::ephemeral()),
            ),
        )
        .await
        .expect("server startup timed out")
        .expect("server startup failed");
        assert!(!tools.is_empty());
        if name == "filesystem" {
            assert!(tools.iter().any(|tool| tool.name == "list_directory"));
            assert!(tools.iter().any(|tool| tool.name == "read_file"));
        }
        println!(
            "{} server listed {} tools with restricted environment",
            name,
            tools.len()
        );
        client
            .close_with_timeout(Duration::from_secs(3))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn manual_agent_tool_calls_still_require_permission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        crate::PrismConfig {
            listen_port: 0,
            ..Default::default()
        }
        .save(&path)
        .unwrap();
        let gateway = crate::Gateway::start_with_credentials(
            path,
            dir.path().join("audit.jsonl"),
            Arc::new(MemoryStore::default()),
        )
        .await
        .unwrap();
        let script = r#"
import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if 'id' not in req: continue
    if req['method'] == 'initialize':
        result = {'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
    elif req['method'] == 'tools/list':
        result = {'tools':[{'name':'verify','inputSchema':{'type':'object'}}]}
    else:
        result = {'content':[{'type':'text','text':'tool executed'}]}
    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}), flush=True)
"#;
        gateway
            .add_server(ServerConfig {
                id: "fixture".into(),
                name: "fixture".into(),
                command: "python3".into(),
                args: vec!["-u".into(), "-c".into(), script.into()],
                env: Default::default(),
                enabled: true,
                credential_ref: None,
                url: None,
                auth: crate::config::HttpAuth::None,
                headers: Default::default(),
                oauth_ref: None,
                hidden_tools: Default::default(),
                hook: None,
            })
            .await
            .unwrap();
        let token = gateway.create_manual_agent("manual").await.unwrap();
        let agent_id = gateway.authenticate(&token.token).await.unwrap();
        for verdict in ["deny", "allow"] {
            let gateway_for_call = gateway.clone();
            let caller = agent_id.clone();
            let call = tokio::spawn(async move {
                gateway_for_call
                    .handle_call_tool(CallToolRequestParams::new("fixture__verify"), Some(&caller))
                    .await
                    .unwrap()
            });
            let pending = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(pending) = gateway.pending().await.into_iter().next() {
                        break pending;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(pending.agent_id, agent_id);
            gateway
                .decide(
                    &pending.id,
                    serde_json::from_value(serde_json::json!({"verdict":verdict,"scope":"once"}))
                        .unwrap(),
                )
                .await
                .unwrap();
            let result = call.await.unwrap();
            assert_eq!(result.is_error.unwrap_or(false), verdict == "deny");
            assert_eq!(
                serde_json::to_string(&result)
                    .unwrap()
                    .contains("tool executed"),
                verdict == "allow"
            );
        }
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn migrated_launch_settings_start_restart_and_do_not_leak_backend_errors() {
        // A small real stdio peer verifies that the child received its original argv/env.
        let script = r#"
import json, os, sys
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request:
        continue
    method = request['method']
    if method == 'initialize':
        result = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'fixture', 'version': '1'}}
    elif method == 'tools/list':
        result = {'tools': [{'name': 'verify', 'inputSchema': {'type': 'object'}}]}
    else:
        assert sys.argv[1] == 'argument-secret'
        assert os.environ['CUSTOM_VALUE'] == 'environment-secret'
        if request['params']['name'] == 'leak':
            print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'error': {'code': -32603, 'message': 'environment-secret argument-secret'}}), flush=True)
            continue
        result = {'content': [{'type': 'text', 'text': 'credentials verified'}]}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
"#;
        let store = Arc::new(MemoryStore::default());
        let mut server = ServerConfig {
            id: "fixture".into(),
            name: "fixture".into(),
            command: "python3".into(),
            args: vec![
                "-u".into(),
                "-c".into(),
                script.into(),
                "argument-secret".into(),
            ],
            env: std::collections::BTreeMap::from([(
                "CUSTOM_VALUE".into(),
                "environment-secret".into(),
            )]),
            enabled: true,
            credential_ref: None,
            url: None,
            auth: crate::config::HttpAuth::None,
            headers: Default::default(),
            oauth_ref: None,
            hidden_tools: Default::default(),
            hook: None,
        };
        protect_server(store.as_ref(), &mut server).unwrap();
        let (events, _) = crate::events::channel();
        let manager = BackendManager::new(events, store);
        manager.start(server.clone()).await;
        assert_eq!(manager.running_count().await, 1);
        let result = manager
            .call_tool("fixture", "verify", serde_json::json!({}))
            .await
            .unwrap();
        assert!(serde_json::to_string(&result)
            .unwrap()
            .contains("credentials verified"));
        let error = manager
            .call_tool("fixture", "leak", serde_json::json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("details omitted"));
        assert!(!error.contains("environment-secret"));
        assert!(!error.contains("argument-secret"));
        manager.restart("fixture").await.unwrap();
        assert_eq!(manager.running_count().await, 1);
        let view =
            serde_json::to_string(&ServerView::from_parts(server, BackendStatus::Stopped)).unwrap();
        assert!(!view.contains("argument-secret"));
        assert!(!view.contains("environment-secret"));
        manager.remove("fixture").await;
    }

    #[tokio::test]
    async fn stdio_server_handshake_failure_captures_stderr_and_logs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        crate::PrismConfig {
            listen_port: 0,
            ..Default::default()
        }
        .save(&path)
        .unwrap();
        let gateway = crate::Gateway::start_with_credentials(
            path,
            dir.path().join("audit.jsonl"),
            Arc::new(MemoryStore::default()),
        )
        .await
        .unwrap();
        let script = r#"
import sys
sys.stderr.write("FATAL_TEST_ERROR: initialization failed missing db connection\n")
sys.exit(1)
"#;
        let server = gateway
            .add_server(ServerConfig {
                id: "broken-server".into(),
                name: "broken-server".into(),
                command: "python3".into(),
                args: vec!["-u".into(), "-c".into(), script.into()],
                env: Default::default(),
                enabled: true,
                credential_ref: None,
                url: None,
                auth: crate::config::HttpAuth::None,
                headers: Default::default(),
                oauth_ref: None,
                hidden_tools: Default::default(),
                hook: None,
            })
            .await
            .unwrap();

        let snapshot = gateway.backends.snapshot().await;
        let entry = snapshot
            .iter()
            .find(|(s, _)| s.id == server.id)
            .expect("found server");
        match &entry.1 {
            BackendStatus::Failed { error } => {
                assert!(
                    error.contains("FATAL_TEST_ERROR"),
                    "expected FATAL_TEST_ERROR in stderr, error was: {error}"
                );
                assert!(
                    error.contains("initialization failed missing db connection"),
                    "expected full message in stderr, error was: {error}"
                );
            }
            other => panic!("expected failed status, got: {other:?}"),
        }

        let servers_log_path = gateway.mcp_servers_traffic_path();
        let content = std::fs::read_to_string(servers_log_path).unwrap();
        assert!(content.contains("handshake_failed"));
        assert!(content.contains("FATAL_TEST_ERROR"));
    }
}

