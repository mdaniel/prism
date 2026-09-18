use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use chrono::Utc;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, DiscoverResult,
    Implementation, InitializeRequestParams, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, SubscriptionFilter,
    Tool,
};
use rmcp::service::{Peer, RequestContext, SubscriptionContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::{ErrorData as McpError, RoleServer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::approval::{
    ApprovalRegistry, Decision, DecisionScope, DecisionTarget, DecisionVerdict, HoldOutcome,
    HoldReason, PendingCall, TIMEOUT_MESSAGE,
};
use crate::audit::{AuditEntry, AuditLog, AuditSource, AuditVerdict};
use crate::backend::{BackendManager, BackendStatus, ServerView};
use crate::config::{
    AgentConfig, AgentStatus, Attention, HttpAuth, ListenAddress, PanelAnchor, Posture,
    PrismConfig, Rule, RuleDecision, RuleScope, ServerConfig, TimeoutBehavior,
};
use crate::error::{Error, Result};
use crate::events::{channel, EventReceiver, EventSender, GatewayEvent};
use crate::listener::{socket, BindFailure, Listener, ListenerState, Serving};
use crate::oauth::{self, AuthenticatedAgent, OAuthState, TokenView};
use crate::policy::{self, Decider, ToolAnnotations, Verdict};

/// Live gateway status for the desktop UI.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayStatus {
    /// The port agents dial: the bound one while listening, otherwise the configured one.
    pub listen_port: u16,
    pub listening: bool,
    /// Why agents cannot connect, when they cannot.
    pub listener: ListenerState,
    pub listen_address: ListenAddress,
    /// The MCP URL for agents on other machines, while the listener is on the network and
    /// this machine has a route out.
    pub network_url: Option<String>,
    pub servers_running: usize,
    pub servers_total: usize,
    pub agent_count: usize,
    pub pending_count: usize,
    pub pending_agents: usize,
    /// Approved agents whose client is signing in again and waiting for consent.
    pub pending_signins: usize,
    pub auto_open_on_pending: bool,
    pub do_not_disturb: bool,
}

/// Operator-level knobs, the ones that are not about one agent or one rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub on_timeout: TimeoutBehavior,
    pub do_not_disturb: bool,
    pub rate_limit_per_minute: Option<u32>,
    pub hold_timeout_secs: u64,
    pub auto_open_on_pending: bool,
    /// Which corner the panel opens in; `auto` follows the desktop's bar.
    pub panel_anchor: PanelAnchor,
    /// The global shortcut as configured; `None` is the built-in one, empty turns it off.
    /// Shown in the panel, applied at the next launch.
    pub panel_shortcut: Option<String>,
}

/// A rule as the panel creates it. Same triple as an existing rule replaces that rule.
#[derive(Debug, Clone, Deserialize)]
pub struct NewRule {
    pub agent_id: Option<String>,
    pub server_id: Option<String>,
    pub tool: Option<String>,
    pub decision: RuleDecision,
    #[serde(default)]
    pub attention: Option<Attention>,
    #[serde(default = "always")]
    pub scope: RuleScope,
    /// Time box in minutes; `None` means until removed.
    #[serde(default)]
    pub minutes: Option<u32>,
}

fn always() -> RuleScope {
    RuleScope::Always
}

/// One tool on one server, as the panel lists it for per-tool overrides.
#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: Option<String>,
    pub read_only: bool,
    pub destructive: bool,
    /// False when the panel hid it: agents neither list nor call it.
    pub exposed: bool,
}

/// The gateway URL and a generic `mcp.json` block pointing at it.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectSnippet {
    pub url: String,
    pub mcp_json: String,
    /// The URL for agents on other machines; `None` while the listener is loopback only.
    pub network_url: Option<String>,
}

/// An agent as the panel sees it: its config plus whether a session is open right now.
#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    #[serde(flatten)]
    pub agent: AgentConfig,
    pub connected: bool,
    /// Live tokens this agent holds. Empty for agents that connect unauthenticated.
    pub tokens: Vec<TokenView>,
    /// The OAuth clients that sign in as this agent: one per scope or install a harness
    /// registered from. Empty for manual agents and harnesses seen only through hooks.
    pub clients: Vec<ClientView>,
}

/// One registered OAuth client, as the panel lists it under its agent.
#[derive(Debug, Clone, Serialize)]
pub struct ClientView {
    pub client_id: String,
    pub client_name: String,
    pub created_at: chrono::DateTime<Utc>,
    pub origin: Option<String>,
    /// Holds a live token.
    pub signed_in: bool,
}

/// Presence for a legacy session or an active stateless request/notification stream.
struct SessionEntry {
    agent_id: String,
    /// Only legacy sessions accept unsolicited peer notifications.
    peer: Option<Peer<RoleServer>>,
}

/// Dropping a tool request records cancellation even when the transport drops
/// the future before it can return an error response.
struct CallAuditGuard<'a> {
    audit: &'a AuditLog,
    entry: Option<AuditEntry>,
    started: Instant,
}

impl Drop for CallAuditGuard<'_> {
    fn drop(&mut self) {
        if let Some(mut entry) = self.entry.take() {
            entry.duration_ms = self.started.elapsed().as_millis() as u64;
            self.audit.record(entry);
        }
    }
}

struct HoldEventGuard {
    events: EventSender,
    id: Option<String>,
}

impl Drop for HoldEventGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = self.events.send(GatewayEvent::CallCancelled { id });
        }
    }
}

/// The MCP gateway agents connect to.
pub struct Gateway {
    pub(crate) config_path: PathBuf,
    pub(crate) config: RwLock<PrismConfig>,
    backends: BackendManager,
    credentials: Arc<dyn crate::credentials::CredentialStore>,
    approval: ApprovalRegistry,
    audit: AuditLog,
    pub(crate) mcp_traffic: Arc<crate::mcp_traffic::McpTrafficLogger>,
    pub(crate) events: EventSender,
    shutdown: CancellationToken,
    listener: Listener,
    pub(crate) oauth: OAuthState,
    sessions: std::sync::Mutex<HashMap<String, SessionEntry>>,
    /// Call timestamps per agent for the rate tripwire; trimmed to the last minute on each check.
    calls: std::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
    /// Secret path segment of the host hook URL. Lives in the data dir; rotatable from the panel.
    hook_token: std::sync::RwLock<String>,
    hook_token_path: PathBuf,
    native_budget: std::sync::Mutex<crate::native::EventBudget>,
    native_last: std::sync::Mutex<HashMap<String, chrono::DateTime<Utc>>>,
}

impl Gateway {
    /// Load config, start backends, bind Streamable HTTP on the loopback port. A port that
    /// cannot be bound does not stop the app: the gateway comes up with the clash in its
    /// status so the panel can show it, and `retry_listener` tries again.
    pub async fn start(
        config_path: impl AsRef<Path>,
        audit_path: impl AsRef<Path>,
    ) -> Result<Arc<Self>> {
        Self::start_with_credentials(
            config_path.as_ref().to_path_buf(),
            audit_path.as_ref().to_path_buf(),
            Arc::new(crate::credentials::NativeStore::default()),
        )
        .await
    }

    pub(crate) async fn start_with_credentials(
        config_path: PathBuf,
        audit_path: PathBuf,
        credentials: Arc<dyn crate::credentials::CredentialStore>,
    ) -> Result<Arc<Self>> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
                    .add_directive("rmcp=off".parse().expect("valid log directive")),
            )
            .try_init();

        // Repair both locations even if a locked credential store later prevents startup.
        crate::storage::prepare(&config_path)?;
        let (events, _) = channel();
        let audit_events = events.clone();
        let hook_token_path = audit_path
            .parent()
            .map(|dir| dir.join("hook-token"))
            .unwrap_or_else(|| PathBuf::from("hook-token"));
        let token_path = hook_token_path.clone();
        let audit_path_clone = audit_path.clone();
        let (audit, hook_token) = tokio::task::spawn_blocking(move || {
            let audit = AuditLog::new(audit_path_clone, audit_events)?;
            let token = load_or_create_hook_token(&token_path)?;
            Ok::<_, Error>((audit, token))
        })
        .await
        .map_err(|_| Error::Gateway("audit storage setup could not complete".into()))??;
        let path = config_path.clone();
        let store = credentials.clone();
        let config = tokio::task::spawn_blocking(move || {
            crate::storage::prepare(&path)?;
            let mut config = if path.exists() {
                PrismConfig::load(&path)?
            } else {
                PrismConfig::default()
            };
            crate::oauth::prune_unused_clients(&mut config, chrono::Utc::now());
            crate::credentials::migrate(&config, &path, store.as_ref())
        })
        .await
        .map_err(|_| Error::Gateway("credential migration could not complete".into()))??;
        let listen_port = config.listen_port;
        let listen_address = config.listen_address;
        let backends = BackendManager::new(events.clone(), credentials.clone());
        let shutdown = CancellationToken::new();

        let mcp_traffic_path = audit_path.with_file_name("mcp.jsonl");
        let mcp_traffic = Arc::new(crate::mcp_traffic::McpTrafficLogger::new(&mcp_traffic_path)?);
        let gateway = Arc::new(Self {
            config_path,
            config: RwLock::new(config.clone()),
            backends,
            credentials,
            approval: ApprovalRegistry::new(),
            audit,
            mcp_traffic,
            events,
            shutdown: shutdown.clone(),
            listener: Listener::idle(listen_port),
            sessions: std::sync::Mutex::new(HashMap::new()),
            calls: std::sync::Mutex::new(HashMap::new()),
            oauth: OAuthState::default(),
            hook_token: std::sync::RwLock::new(hook_token),
            hook_token_path,
            native_budget: std::sync::Mutex::new(Default::default()),
            native_last: std::sync::Mutex::new(HashMap::new()),
        });

        for server in config.servers.into_iter().filter(|s| s.enabled) {
            gateway.backends.start(server).await;
        }

        if let Err(failure) = gateway.bind(listen_address, listen_port).await {
            warn!(port = listen_port, "{}", failure.message(listen_port));
            gateway.listener.set_state(failure.state(listen_port));
        }
        // Modern streams observe the same backend events in `listen`; legacy
        // peers need the corresponding unsolicited session notification.
        let mut backend_events = gateway.subscribe();
        let weak_backend = Arc::downgrade(&gateway);
        let backend_stop = gateway.shutdown.clone();
        tokio::spawn(async move {
            loop {
                let changed = tokio::select! {
                    _ = backend_stop.cancelled() => break,
                    event = backend_events.recv() => match event {
                        Ok(GatewayEvent::ServerStatus { .. } | GatewayEvent::ToolsChanged { .. }) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        _ => false,
                    },
                };
                if changed {
                    let Some(gateway) = weak_backend.upgrade() else {
                        break;
                    };
                    let agents: std::collections::HashSet<_> = gateway
                        .sessions
                        .lock()
                        .map(|sessions| {
                            sessions
                                .values()
                                .filter(|entry| entry.peer.is_some())
                                .map(|entry| entry.agent_id.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    for agent in agents {
                        tokio::select! {
                            _ = backend_stop.cancelled() => return,
                            _ = gateway.notify_tools_changed(&agent) => {},
                        }
                    }
                }
            }
        });
        let weak = Arc::downgrade(&gateway);
        let stop = gateway.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60 * 60)) => {
                        let Some(gateway) = weak.upgrade() else { break; };
                        let _ = tokio::task::spawn_blocking(move || {
                            if gateway.audit.cleanup().is_err() {
                                warn!("audit retention cleanup failed");
                            }
                        }).await;
                    }
                }
            }
        });
        if gateway.listener.is_listening() {
            info!(
                port = gateway.listen_port(),
                address = %listen_address.ip(),
                "prism gateway listening"
            );
        }
        Ok(gateway)
    }

    pub async fn status(&self) -> GatewayStatus {
        let config = self.config.read().await;
        GatewayStatus {
            listen_port: self.listen_port(),
            listening: !self.shutdown.is_cancelled() && self.listener.is_listening(),
            listener: if self.shutdown.is_cancelled() {
                ListenerState::Stopped
            } else {
                self.listener.state()
            },
            listen_address: config.listen_address,
            network_url: self.network_url(),
            servers_running: self.backends.running_count().await,
            servers_total: config.servers.len(),
            agent_count: config.agents.len(),
            pending_count: self.approval.list().await.len(),
            pending_agents: config
                .agents
                .iter()
                .filter(|a| a.status == AgentStatus::Pending)
                .count(),
            pending_signins: self
                .pending_signins()
                .iter()
                .filter(|s| s.needs_consent)
                .count(),
            auto_open_on_pending: config.auto_open_on_pending,
            do_not_disturb: config.do_not_disturb,
        }
    }

    pub async fn servers(&self) -> Vec<ServerView> {
        let live = self.backends.snapshot().await;
        let config = self.config.read().await;
        config
            .servers
            .iter()
            .map(|cfg| {
                let status = live
                    .iter()
                    .find(|(c, _)| c.id == cfg.id)
                    .map(|(_, s)| s.clone())
                    .unwrap_or(BackendStatus::Stopped);
                ServerView::from_parts(cfg.clone(), status)
            })
            .collect()
    }

    pub async fn add_server(&self, mut server: ServerConfig) -> Result<ServerConfig> {
        if server.credential_ref.is_some() {
            return Err(Error::Invalid(
                "new servers must supply launch values, not credential references".into(),
            ));
        }
        if server.id.is_empty() {
            server.id = uuid::Uuid::new_v4().to_string();
        }
        if server.name.trim().is_empty() {
            return Err(Error::Invalid("server name is required".into()));
        }
        if server.oauth_ref.is_some() {
            return Err(Error::Invalid(
                "new servers must not carry an OAuth credential reference".into(),
            ));
        }
        match server.url.as_deref() {
            Some(url) => {
                server.url = Some(crate::remote::validate_url(url)?);
                if !server.command.trim().is_empty()
                    || !server.args.is_empty()
                    || !server.env.is_empty()
                {
                    return Err(Error::Invalid(
                        "a remote server has a URL, not a command".into(),
                    ));
                }
                server.command.clear();
                match server.auth {
                    HttpAuth::Header if server.headers.is_empty() => {
                        return Err(Error::Invalid("header auth needs a header".into()));
                    }
                    HttpAuth::Oauth => server.oauth_ref = Some(uuid::Uuid::new_v4().to_string()),
                    _ => {}
                }
            }
            None => {
                if server.command.trim().is_empty() {
                    return Err(Error::Invalid("server command is required".into()));
                }
                if !server.headers.is_empty() || server.auth != HttpAuth::None {
                    return Err(Error::Invalid(
                        "headers and auth apply to remote servers only".into(),
                    ));
                }
            }
        }
        {
            let mut config = self.config.write().await;
            if config
                .servers
                .iter()
                .any(|s| s.id == server.id || s.name == server.name)
            {
                return Err(Error::AlreadyExists(format!("server {}", server.name)));
            }
            let store = self.credentials.clone();
            server = tokio::task::spawn_blocking(move || {
                crate::credentials::protect_server(store.as_ref(), &mut server)?;
                Ok::<_, Error>(server)
            })
            .await
            .map_err(|_| Error::Gateway("could not store server credentials".into()))??;
            let mut updated = config.clone();
            updated.servers.push(server.clone());
            // On an uncertain disk failure, keep the credential entry for recovery.
            updated.save(&self.config_path)?;
            *config = updated;
        }
        self.backends.start(server.clone()).await;
        Ok(server)
    }

    pub async fn remove_server(&self, server_id: &str) -> Result<()> {
        let removed = {
            let mut config = self.config.write().await;
            let server = config
                .servers
                .iter()
                .find(|s| s.id == server_id)
                .ok_or_else(|| Error::NotFound(format!("server {server_id}")))?
                .clone();
            let mut updated = config.clone();
            updated.servers.retain(|s| s.id != server_id);
            updated.save(&self.config_path)?;
            *config = updated;
            server
        };
        self.backends.remove(server_id).await;
        // The server is already gone from the config, so both cleanups run whatever the other
        // one does; the first failure is reported once the second has been tried.
        let store = self.credentials.clone();
        let credential_ref = removed.credential_ref.clone();
        let launch = tokio::task::spawn_blocking(move || match &credential_ref {
            Some(id) => crate::credentials::delete(store.as_ref(), id),
            None => Ok(()),
        })
        .await
        .unwrap_or_else(|_| {
            Err(Error::Gateway(
                "server removed, but credential cleanup could not complete".into(),
            ))
        });
        // Same as Sign out: revoke at the provider when it can, then forget the tokens here.
        let tokens = crate::remote::sign_out(&removed, self.credentials.clone()).await;
        launch.and(tokens)
    }

    pub async fn restart_server(&self, server_id: &str) -> Result<()> {
        self.backends.restart(server_id).await
    }

    /// Show or hide one tool of a server for every agent. Saved to config; the next list or call sees it.
    pub async fn set_tool_exposed(&self, server_id: &str, tool: &str, exposed: bool) -> Result<()> {
        let mut config = self.config.write().await;
        let mut updated = config.clone();
        let server = updated
            .servers
            .iter_mut()
            .find(|s| s.id == server_id)
            .ok_or_else(|| Error::NotFound(format!("server {server_id}")))?;
        let changed = if exposed {
            server.hidden_tools.remove(tool)
        } else {
            server.hidden_tools.insert(tool.to_string())
        };
        if changed {
            updated.save(&self.config_path)?;
            *config = updated;
        }
        drop(config);
        if changed {
            let _ = self.events.send(GatewayEvent::ToolsChanged {
                server_id: server_id.to_string(),
            });
        }
        Ok(())
    }

    /// The hidden set per server, from the live config rather than a backend's start-time copy.
    async fn hidden_tools(&self) -> HashMap<String, std::collections::BTreeSet<String>> {
        self.config
            .read()
            .await
            .servers
            .iter()
            .filter(|s| !s.hidden_tools.is_empty())
            .map(|s| (s.id.clone(), s.hidden_tools.clone()))
            .collect()
    }

    async fn server_config(&self, server_id: &str) -> Result<ServerConfig> {
        self.config
            .read()
            .await
            .servers
            .iter()
            .find(|s| s.id == server_id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("server {server_id}")))
    }

    /// Start a browser sign-in for an OAuth server and return the URL to open. The server
    /// reconnects on its own once the browser comes back; a failure lands in its status.
    pub async fn sign_in_server(self: &Arc<Self>, server_id: &str) -> Result<String> {
        let config = self.server_config(server_id).await?;
        if config.auth != HttpAuth::Oauth {
            return Err(Error::Invalid("this server does not use OAuth".into()));
        }
        let sign_in = crate::remote::begin_sign_in(&config, self.credentials.clone()).await?;
        let url = sign_in.url;
        let gateway = self.clone();
        tokio::spawn(async move {
            let outcome = sign_in
                .done
                .await
                .unwrap_or_else(|_| Err(Error::Gateway("sign-in was cancelled".into())));
            match outcome {
                Ok(()) => {
                    gateway.backends.stop(&config.id).await;
                    gateway.backends.start(config).await;
                }
                Err(err) => {
                    gateway
                        .backends
                        .mark_failed(&config.id, err.to_string())
                        .await
                }
            }
        });
        Ok(url)
    }

    /// Forget an OAuth server's tokens and registration. It shows as needing a sign-in.
    pub async fn sign_out_server(&self, server_id: &str) -> Result<()> {
        let config = self.server_config(server_id).await?;
        if config.auth != HttpAuth::Oauth {
            return Err(Error::Invalid("this server does not use OAuth".into()));
        }
        self.backends.stop(server_id).await;
        crate::remote::sign_out(&config, self.credentials.clone()).await?;
        self.backends.start(config).await;
        Ok(())
    }

    pub async fn agents(&self) -> Vec<AgentView> {
        let connected: std::collections::HashSet<String> = self
            .sessions
            .lock()
            .map(|s| s.values().map(|e| e.agent_id.clone()).collect())
            .unwrap_or_default();
        let now = Utc::now();
        let config = self.config.read().await;
        config
            .agents
            .iter()
            .cloned()
            .map(|agent| {
                let client_ids = config.agent_client_ids(&agent.id);
                AgentView {
                    connected: connected.contains(&agent.id),
                    tokens: config
                        .tokens
                        .iter()
                        .filter(|t| t.agent_id == agent.id && !t.is_expired(now))
                        .map(|t| TokenView {
                            kind: t.kind,
                            created_at: t.created_at,
                            expires_at: t.expires_at,
                        })
                        .collect(),
                    clients: config
                        .clients
                        .iter()
                        .filter(|c| client_ids.contains(&c.client_id))
                        .map(|c| ClientView {
                            client_id: c.client_id.clone(),
                            client_name: c.client_name.clone(),
                            created_at: c.created_at,
                            origin: c.origin.clone(),
                            signed_in: config.tokens.iter().any(|t| {
                                t.client_id.as_deref() == Some(c.client_id.as_str())
                                    && !t.is_expired(now)
                            }),
                        })
                        .collect(),
                    agent,
                }
            })
            .collect()
    }

    /// Approve or deny an agent. Every open session for that agent is told its tool list
    /// changed, so clients refetch and either see the tools or lose them.
    pub async fn decide_agent(&self, agent_id: &str, approve: bool) -> Result<()> {
        let status = if approve {
            AgentStatus::Approved
        } else {
            AgentStatus::Denied
        };
        {
            let mut config = self.config.write().await;
            let agent = config
                .agents
                .iter_mut()
                .find(|a| a.id == agent_id)
                .ok_or_else(|| Error::NotFound(format!("agent {agent_id}")))?;
            agent.status = status;
            agent.decided_at = Some(Utc::now());
            if !approve {
                // Deny is a sign-out too: nothing it holds keeps working.
                config.tokens.retain(|t| t.agent_id != agent_id);
            }
            config.save(&self.config_path)?;
        }
        self.resolve_authorization(agent_id, approve);
        let _ = self.events.send(GatewayEvent::AgentDecided {
            agent_id: agent_id.to_string(),
            status,
        });
        self.notify_tools_changed(agent_id).await;
        Ok(())
    }

    pub async fn remove_agent(&self, agent_id: &str) -> Result<()> {
        {
            let mut config = self.config.write().await;
            let before = config.agents.len();
            Self::forget_credentials(&mut config, agent_id);
            config.agents.retain(|a| a.id != agent_id);
            if config.agents.len() == before {
                return Err(Error::NotFound(format!("agent {agent_id}")));
            }
            config
                .rules
                .retain(|r| r.agent_id.as_deref() != Some(agent_id));
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::RulesChanged);
        self.resolve_authorization(agent_id, false);
        let _ = self.events.send(GatewayEvent::AgentDecided {
            agent_id: agent_id.to_string(),
            status: AgentStatus::Denied,
        });
        self.notify_tools_changed(agent_id).await;
        Ok(())
    }

    async fn notify_tools_changed(&self, agent_id: &str) {
        let peers: Vec<Peer<RoleServer>> = self
            .sessions
            .lock()
            .map(|s| {
                s.values()
                    .filter(|e| e.agent_id == agent_id)
                    .filter_map(|e| e.peer.clone())
                    .collect()
            })
            .unwrap_or_default();
        for peer in peers {
            if let Err(err) = peer.notify_tool_list_changed().await {
                warn!(%err, agent_id, "could not notify session of tool list change");
            }
        }
    }

    /// Track an authenticated legacy session or active stateless request. The
    /// bearer names the agent; client metadata is display information only.
    async fn register_authenticated_presence(
        &self,
        session_id: &str,
        agent_id: &str,
        client_version: Option<&str>,
        peer: Option<Peer<RoleServer>>,
    ) -> Option<AgentConfig> {
        let agent = {
            let mut config = self.config.write().await;
            let agent = config.agents.iter_mut().find(|a| a.id == agent_id)?;
            if let Some(v) = client_version {
                agent.client_version = Some(v.to_string());
            }
            agent.clone()
        };
        let newly_connected = if let Ok(mut sessions) = self.sessions.lock() {
            let connected = sessions.values().any(|entry| entry.agent_id == agent.id);
            sessions.insert(
                session_id.to_string(),
                SessionEntry {
                    agent_id: agent.id.clone(),
                    peer,
                },
            );
            !connected
        } else {
            false
        };
        if newly_connected {
            let _ = self.events.send(GatewayEvent::AgentConnected {
                agent_id: agent.id.clone(),
            });
        }
        Some(agent)
    }

    fn unregister_session(&self, session_id: &str) {
        let removed = self.sessions.lock().ok().and_then(|mut s| {
            let entry = s.remove(session_id)?;
            (!s.values().any(|other| other.agent_id == entry.agent_id)).then_some(entry)
        });
        if let Some(entry) = removed {
            let _ = self.events.send(GatewayEvent::AgentDisconnected {
                agent_id: entry.agent_id,
            });
        }
    }

    pub(crate) async fn agent_by_id(&self, agent_id: &str) -> Option<AgentConfig> {
        self.config
            .read()
            .await
            .agents
            .iter()
            .find(|a| a.id == agent_id)
            .cloned()
    }

    pub async fn pending(&self) -> Vec<PendingCall> {
        self.approval.list().await
    }

    pub async fn decide(&self, id: &str, decision: Decision) -> Result<()> {
        if let Some(condition) = &decision.condition {
            policy::Condition::parse(condition).map_err(Error::Invalid)?;
        }
        let call = self.approval.decide(id, decision.clone()).await?;
        let _ = self.events.send(GatewayEvent::CallDecided {
            id: id.to_string(),
            decision: decision.clone(),
        });
        if decision.scope != DecisionScope::Once {
            self.append_rule_for(&call, decision).await?;
        }
        Ok(())
    }

    /// Current rules, with expired time boxes pruned on the way out.
    pub async fn rules(&self) -> Vec<Rule> {
        let now = Utc::now();
        let stale = self
            .config
            .read()
            .await
            .rules
            .iter()
            .any(|r| r.is_expired(now));
        if stale {
            let mut config = self.config.write().await;
            config.rules.retain(|r| !r.is_expired(now));
            if let Err(err) = config.save(&self.config_path) {
                warn!(%err, "could not persist pruned rules");
            }
            drop(config);
            let _ = self.events.send(GatewayEvent::RulesChanged);
        }
        self.config
            .read()
            .await
            .rules
            .iter()
            .cloned()
            .map(|mut rule| {
                rule.condition_error = rule
                    .condition
                    .as_ref()
                    .and_then(|c| policy::Condition::parse(c).err());
                rule
            })
            .collect()
    }

    /// Add a rule from the panel. A rule on the same agent, server, and tool is replaced.
    pub async fn add_rule(&self, new: NewRule) -> Result<Rule> {
        if new.agent_id.is_none() && new.server_id.is_none() && new.tool.is_none() {
            return Err(Error::Invalid(
                "a rule needs at least an agent, a server, or a tool".into(),
            ));
        }
        let now = Utc::now();
        let rule = Rule {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: new.agent_id,
            server_id: new.server_id,
            tool: new.tool.filter(|t| !t.trim().is_empty()),
            decision: new.decision,
            attention: new.attention,
            scope: new.scope,
            expires_at: new
                .minutes
                .map(|m| now + chrono::Duration::minutes(i64::from(m))),
            condition: None,
            condition_error: None,
            created_at: now,
        };
        self.upsert_rule(rule.clone()).await?;
        Ok(rule)
    }

    async fn upsert_rule(&self, rule: Rule) -> Result<()> {
        {
            let mut config = self.config.write().await;
            config.rules.retain(|r| {
                !(r.agent_id == rule.agent_id
                    && r.server_id == rule.server_id
                    && r.tool == rule.tool
                    && r.condition == rule.condition)
            });
            config.rules.push(rule);
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::RulesChanged);
        Ok(())
    }

    /// Change how an agent behaves when no rule matches, and how loudly its calls are surfaced.
    pub async fn set_agent_policy(
        &self,
        agent_id: &str,
        posture: Option<Posture>,
        attention: Option<Attention>,
    ) -> Result<AgentConfig> {
        let agent = {
            let mut config = self.config.write().await;
            let agent = config
                .agents
                .iter_mut()
                .find(|a| a.id == agent_id)
                .ok_or_else(|| Error::NotFound(format!("agent {agent_id}")))?;
            if let Some(p) = posture {
                agent.posture = p;
            }
            if let Some(a) = attention {
                agent.attention = a;
            }
            let agent = agent.clone();
            config.save(&self.config_path)?;
            agent
        };
        let _ = self.events.send(GatewayEvent::AgentUpdated {
            agent_id: agent_id.to_string(),
        });
        Ok(agent)
    }

    pub async fn settings(&self) -> Settings {
        let config = self.config.read().await;
        Settings {
            on_timeout: config.on_timeout,
            do_not_disturb: config.do_not_disturb,
            rate_limit_per_minute: config.rate_limit_per_minute,
            hold_timeout_secs: config.hold_timeout_secs,
            auto_open_on_pending: config.auto_open_on_pending,
            panel_anchor: config.panel_anchor,
            panel_shortcut: config.panel_shortcut.clone(),
        }
    }

    pub async fn set_settings(&self, settings: Settings) -> Result<()> {
        if settings.hold_timeout_secs < 10 {
            return Err(Error::Invalid(
                "hold timeout must be at least 10 seconds".into(),
            ));
        }
        {
            let mut config = self.config.write().await;
            config.on_timeout = settings.on_timeout;
            config.do_not_disturb = settings.do_not_disturb;
            config.rate_limit_per_minute = settings.rate_limit_per_minute.filter(|n| *n > 0);
            config.hold_timeout_secs = settings.hold_timeout_secs;
            config.auto_open_on_pending = settings.auto_open_on_pending;
            config.panel_anchor = settings.panel_anchor;
            config.panel_shortcut = settings.panel_shortcut;
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::SettingsChanged);
        Ok(())
    }

    /// Tools one server currently exposes, for per-tool overrides in the panel.
    pub async fn server_tools(&self, server_id: &str) -> Vec<ToolInfo> {
        let hidden = self.hidden_tools().await;
        self.backends
            .list_tools(false)
            .await
            .into_iter()
            .filter(|(server, _)| server.id == server_id)
            .map(|(_, tool)| ToolInfo {
                exposed: !is_hidden(&hidden, server_id, tool.name.as_ref()),
                name: tool.name.to_string(),
                description: tool.description.as_ref().map(|d| d.to_string()),
                read_only: tool
                    .annotations
                    .as_ref()
                    .and_then(|a| a.read_only_hint)
                    .unwrap_or(false),
                destructive: tool
                    .annotations
                    .as_ref()
                    .and_then(|a| a.destructive_hint)
                    .unwrap_or(false),
            })
            .collect()
    }

    /// Record one call attempt and report whether the agent is over `limit` per minute.
    fn rate_tripped(&self, agent_id: &str, limit: u32) -> bool {
        let now = Instant::now();
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        let window = calls.entry(agent_id.to_string()).or_default();
        while window
            .front()
            .is_some_and(|t| now.duration_since(*t) > std::time::Duration::from_secs(60))
        {
            window.pop_front();
        }
        window.push_back(now);
        window.len() as u32 > limit
    }

    pub async fn delete_rule(&self, rule_id: &str) -> Result<()> {
        {
            let mut config = self.config.write().await;
            let before = config.rules.len();
            config.rules.retain(|r| r.id != rule_id);
            if config.rules.len() == before {
                return Err(Error::NotFound(format!("rule {rule_id}")));
            }
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::RulesChanged);
        Ok(())
    }

    pub fn mcp_traffic_path(&self) -> &Path {
        self.mcp_traffic.path()
    }

    /// Compatibility cache feed. Desktop history uses `audit_query` for errors and metadata.
    pub async fn audit(&self, limit: usize) -> Vec<AuditEntry> {
        let audit = self.audit.clone();
        tokio::task::spawn_blocking(move || audit.list(limit))
            .await
            .expect("audit cache worker could not complete")
    }

    pub async fn audit_query(
        &self,
        mut query: crate::audit::AuditQuery,
    ) -> Result<crate::audit::AuditPage> {
        query
            .canonicalization_exclusions
            .extend(self.audit_identity_exclusions().await);
        self.audit.query(query).await
    }

    pub async fn audit_export(
        &self,
        mut query: crate::audit::AuditQuery,
    ) -> Result<crate::audit::AuditExport> {
        query
            .canonicalization_exclusions
            .extend(self.audit_identity_exclusions().await);
        self.audit.export(query).await
    }

    /// Manual registrations share the UUID format with historical OAuth registrations. Their
    /// current config, never a display name or query parameter, keeps their presentation separate.
    async fn audit_identity_exclusions(&self) -> std::collections::HashSet<String> {
        self.config
            .read()
            .await
            .agents
            .iter()
            .filter(|agent| agent.host.is_none() && agent.client_id.is_none())
            .map(|agent| agent.id.clone())
            .collect()
    }

    /// Retained history over local calendar days, with the same window as audit drilldowns.
    pub async fn activity(&self, days: u32) -> Result<crate::activity::ActivitySummary> {
        let exclusions = self.audit_identity_exclusions().await;
        self.audit
            .read(days, move |snapshot| {
                let mut summary = crate::activity::summarize_with_exclusions(
                    snapshot.entries.iter().map(AsRef::as_ref),
                    snapshot.window.days,
                    snapshot.window.snapshot_at,
                    &exclusions,
                );
                summary.window = snapshot.window;
                Ok(summary)
            })
            .await
    }

    // ----- native actions (observe) ------------------------------------------------------

    pub(crate) fn hook_token_matches(&self, candidate: &str) -> bool {
        self.hook_token
            .read()
            .map(|t| crate::native::token_eq(&t, candidate))
            .unwrap_or(false)
    }

    /// The URL an agent host posts its hook events to. Contains the secret; treat like a token.
    pub fn hook_url(&self, host: &str) -> String {
        let token = self
            .hook_token
            .read()
            .map(|t| t.clone())
            .unwrap_or_default();
        format!(
            "http://127.0.0.1:{}/hooks/{host}/{token}",
            self.listen_port()
        )
    }

    /// Replace the hook secret. The old URL stops working at once; hosts need the new one.
    pub async fn rotate_hook_token(&self) -> Result<()> {
        let token = crate::native::new_token();
        let path = self.hook_token_path.clone();
        let bytes = token.clone();
        tokio::task::spawn_blocking(move || crate::storage::atomic_write(&path, bytes.as_bytes()))
            .await
            .map_err(|_| Error::Gateway("hook token write could not complete".into()))??;
        if let Ok(mut current) = self.hook_token.write() {
            *current = token;
        }
        let _ = self.events.send(GatewayEvent::SettingsChanged);
        Ok(())
    }

    pub async fn set_observe_native(&self, on: bool) -> Result<()> {
        {
            let mut config = self.config.write().await;
            config.observe_native = on;
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::SettingsChanged);
        Ok(())
    }

    /// A harness that was just set up gets its agent record now, so the panel lists it before
    /// the first sign-in or hook event. A record you refused stays refused; nothing is revived.
    pub async fn ensure_host_agent(&self, host: &str) -> Result<()> {
        if !crate::native::HOSTS.contains(&host) {
            return Err(Error::NotFound(format!("unknown host {host}")));
        }
        let agent_id = crate::native::harness_agent_id(host, None);
        {
            let mut config = self.config.write().await;
            if config.agents.iter().any(|a| a.id == agent_id) {
                return Ok(());
            }
            config.agents.push(AgentConfig::harness(
                host,
                None,
                AgentStatus::Approved,
                Utc::now(),
            ));
            config.save(&self.config_path)?;
        }
        let _ = self.events.send(GatewayEvent::AgentUpdated { agent_id });
        Ok(())
    }

    /// Coverage and seven local calendar days from retained history, matching drilldowns.
    pub async fn native_status(&self) -> Result<crate::native::NativeStatus> {
        let observe_native = self.config.read().await.observe_native;
        let exclusions = self.audit_identity_exclusions().await;
        let mut last = self
            .native_last
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default();
        let hook_urls: HashMap<_, _> = crate::native::HOSTS
            .iter()
            .map(|host| (host.to_string(), self.hook_url(host)))
            .collect();
        self.audit
            .read(7, move |snapshot| {
                let query = crate::audit::AuditQuery {
                    native_only: true,
                    canonicalization_exclusions: exclusions,
                    ..Default::default()
                };
                let mut actions = 0usize;
                let mut per_host: HashMap<String, usize> = HashMap::new();
                let mut counts: HashMap<String, usize> = HashMap::new();
                let mut host_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();
                for entry in snapshot
                    .entries
                    .iter()
                    .filter(|entry| query.matches(entry, &snapshot.window))
                {
                    let native = entry.native.as_ref().expect("native-only query");
                    actions += 1;
                    let id = crate::audit::canonical_agent_id_excluding(
                        entry,
                        &query.canonicalization_exclusions,
                    );
                    // Match the same presentation id as the drilldown. The persisted raw id and
                    // remote origin suffix remain intact; a display name conveys no authority.
                    let local_host = crate::native::HOSTS
                        .iter()
                        .copied()
                        .find(|host| id.as_ref() == crate::native::harness_agent_id(host, None));
                    if let Some(host) = local_host {
                        *per_host.entry(host.to_string()).or_default() += 1;
                        let seen = last.entry(host.to_string()).or_insert(entry.at);
                        *seen = (*seen).max(entry.at);
                    }
                    if let Some(reason) = &native.would_hold {
                        *counts.entry(reason.clone()).or_default() += 1;
                        if let Some(host) = local_host {
                            *host_counts
                                .entry(host.to_string())
                                .or_default()
                                .entry(reason.clone())
                                .or_default() += 1;
                        }
                    }
                }
                let sorted_reasons = |counts: HashMap<String, usize>| {
                    let mut reasons: Vec<_> = counts
                        .into_iter()
                        .map(|(reason, count)| crate::native::ReasonCount { reason, count })
                        .collect();
                    reasons.sort_by(|a, b| b.count.cmp(&a.count).then(a.reason.cmp(&b.reason)));
                    reasons
                };
                let hosts = crate::native::HOSTS
                    .iter()
                    .map(|host| crate::native::HostStatus {
                        host: host.to_string(),
                        hook_url: hook_urls.get(*host).cloned().unwrap_or_default(),
                        last_event_at: last.get(*host).copied(),
                        actions_7d: per_host.get(*host).copied().unwrap_or(0),
                        by_reason: sorted_reasons(host_counts.remove(*host).unwrap_or_default()),
                    })
                    .collect();
                let by_reason = sorted_reasons(counts);
                Ok(crate::native::NativeStatus {
                    observe_native,
                    last_event_at: last.values().max().copied(),
                    actions_7d: actions,
                    would_hold_7d: by_reason.iter().map(|r| r.count).sum(),
                    by_reason,
                    rules: crate::native::shadow::RULES.to_vec(),
                    hosts,
                    window: snapshot.window,
                })
            })
            .await
    }

    /// JSONL of every retained native shadow hit in the requested local calendar days.
    pub async fn native_export(&self, days: i64) -> Result<String> {
        Ok(self
            .audit
            .export(crate::audit::AuditQuery {
                days: days.clamp(1, 30) as u32,
                native_only: true,
                attention: Some(true),
                ..Default::default()
            })
            .await?
            .jsonl)
    }

    /// One hook event becomes one observed audit entry. Creates the host's agent record on first
    /// contact. A revoked host is refused, so the hook stops being accepted once you deny it.
    pub(crate) async fn record_native(
        &self,
        host: &str,
        observation: crate::native::Observation,
    ) -> Result<()> {
        if !self
            .native_budget
            .lock()
            .map(|mut b| b.admit_event(host, &observation))
            .unwrap_or(false)
        {
            return Ok(());
        }
        let agent_id = format!("host:{host}");
        let now = Utc::now();
        let (observe, agent_name, created) = {
            let mut config = self.config.write().await;
            let created = match config.agents.iter().find(|a| a.id == agent_id) {
                Some(agent) if agent.status == AgentStatus::Denied => {
                    return Err(Error::NotFound(format!("host {host} is revoked")));
                }
                Some(_) => false,
                None => {
                    config.agents.push(AgentConfig::harness(
                        host,
                        None,
                        AgentStatus::Approved,
                        now,
                    ));
                    config.save(&self.config_path)?;
                    true
                }
            };
            let name = config
                .agents
                .iter()
                .find(|a| a.id == agent_id)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| host_display_name(host));
            (config.observe_native, name, created)
        };
        if created {
            let _ = self.events.send(GatewayEvent::AgentUpdated {
                agent_id: agent_id.clone(),
            });
        }
        if !observe {
            return Ok(());
        }
        let home = home_dir();
        let event = &observation.event;
        let cwd = event.cwd.as_deref().map(Path::new);
        let subject = crate::native::subject(
            observation.policy_tool(),
            &event.tool_input,
            cwd,
            home.as_deref(),
        );
        let would_hold = crate::native::shadow::evaluate(
            observation.policy_tool(),
            &event.tool_input,
            cwd,
            home.as_deref(),
        )
        .map(str::to_string);
        let via_prism = self
            .backends
            .list_tools(false)
            .await
            .iter()
            .any(|(server, tool)| observation.matches_prism_tool(host, &server.name, &tool.name));
        if let Ok(mut last) = self.native_last.lock() {
            last.insert(host.to_string(), now);
        }
        let event = observation.event;
        self.audit.record(AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            at: now,
            agent_id,
            agent_name,
            server_id: host.to_string(),
            tool: crate::native::redact_identifier(&event.tool_name),
            // A Goose denial is the host's decision, never a Prism enforcement decision.
            // Antigravity reports completed calls, including errors; it cannot report blocks.
            verdict: observation.verdict,
            source: AuditSource::Observed,
            duration_ms: 0,
            error: None,
            attention: Attention::Silent,
            facets: Vec::new(),
            native: Some(crate::audit::NativeDetail {
                host: host.to_string(),
                session: event
                    .session_id
                    .map(|s| crate::native::redact_identifier(&s)),
                cwd: event.cwd.map(|s| crate::native::redact(&s)),
                subject,
                would_hold,
                agent_type: event
                    .agent_type
                    .map(|s| crate::native::redact_identifier(&s)),
                via_prism,
            }),
        });
        Ok(())
    }

    /// Sync snapshot of the configured panel anchor for window placement callbacks.
    pub fn panel_anchor(&self) -> PanelAnchor {
        self.config
            .try_read()
            .map(|c| c.panel_anchor)
            .unwrap_or_default()
    }

    /// The configured panel shortcut, if the user set one.
    pub fn panel_shortcut(&self) -> Option<String> {
        self.config
            .try_read()
            .ok()
            .and_then(|c| c.panel_shortcut.clone())
    }

    pub fn subscribe(&self) -> EventReceiver {
        self.events.subscribe()
    }

    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let ids: Vec<String> = self
            .backends
            .snapshot()
            .await
            .into_iter()
            .map(|(c, _)| c.id)
            .collect();
        for id in ids {
            self.backends.stop(&id).await;
        }
        self.audit.close();
    }

    pub fn connect_snippet(&self) -> Result<ConnectSnippet> {
        let port = self.listen_port();
        let url = format!("http://127.0.0.1:{port}/mcp");
        let mcp = serde_json::json!({
            "mcpServers": { "prism": { "url": url } }
        });
        Ok(ConnectSnippet {
            url,
            mcp_json: serde_json::to_string_pretty(&mcp)?,
            network_url: self.network_url(),
        })
    }

    async fn append_rule_for(&self, call: &PendingCall, decision: Decision) -> Result<()> {
        let now = Utc::now();
        let (scope, expires_at) = match decision.scope {
            DecisionScope::Once => return Ok(()),
            DecisionScope::Session => (RuleScope::Session, None),
            DecisionScope::Always => (RuleScope::Always, None),
            DecisionScope::For { minutes } => (
                RuleScope::Always,
                Some(now + chrono::Duration::minutes(i64::from(minutes.max(1)))),
            ),
        };
        let (server_id, tool) = match if decision.condition.is_some() {
            DecisionTarget::Tool
        } else {
            decision.target
        } {
            DecisionTarget::Tool => (Some(call.server_id.clone()), Some(call.tool.clone())),
            DecisionTarget::Server => (Some(call.server_id.clone()), None),
            DecisionTarget::Agent => (None, None),
        };
        let rule = Rule {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: Some(call.agent_id.clone()),
            server_id,
            tool,
            decision: match decision.verdict {
                DecisionVerdict::Allow => RuleDecision::Allow,
                DecisionVerdict::Deny => RuleDecision::Deny,
            },
            attention: None,
            scope,
            expires_at,
            condition: decision.condition,
            condition_error: None,
            created_at: now,
        };
        self.upsert_rule(rule).await
    }

    pub(crate) async fn handle_list_tools(&self, agent_id: Option<&str>) -> ListToolsResult {
        let approved = match agent_id {
            Some(id) => self
                .agent_by_id(id)
                .await
                .map(|a| a.is_approved())
                .unwrap_or(false),
            None => false,
        };
        if !approved {
            return ListToolsResult::default();
        }
        let pairs = self.backends.list_tools(false).await;
        let hidden = self.hidden_tools().await;
        let mut tools: Vec<_> = pairs
            .into_iter()
            .filter(|(server, tool)| !is_hidden(&hidden, &server.id, tool.name.as_ref()))
            .map(|(server, tool)| aggregate_tool(&server.name, tool))
            .collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        #[allow(clippy::field_reassign_with_default)]
        {
            let mut result = ListToolsResult::default();
            result.tools = tools;
            result
        }
    }

    pub(crate) async fn handle_call_tool(
        &self,
        request: CallToolRequestParams,
        agent_id: Option<&str>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let started = Instant::now();
        let agent = match agent_id {
            Some(id) => self.agent_by_id(id).await,
            None => None,
        };
        let agent = match agent {
            Some(agent) => agent,
            None => {
                return Err(McpError::invalid_request(
                    "This request has no authenticated agent identity.",
                    None,
                ));
            }
        };
        if !agent.is_approved() {
            let message = format!(
                "Prism has not approved '{}' yet. Open the Prism panel and approve it, then retry.",
                agent.name
            );
            self.audit.record(AuditEntry {
                id: uuid::Uuid::new_v4().to_string(),
                at: Utc::now(),
                agent_id: agent.id.clone(),
                agent_name: agent.name.clone(),
                server_id: String::new(),
                tool: request.name.to_string(),
                verdict: AuditVerdict::Denied,
                source: AuditSource::Unapproved,
                duration_ms: started.elapsed().as_millis() as u64,
                error: Some(message.clone()),
                attention: Attention::Silent,
                native: None,
                facets: Vec::new(),
            });
            return Ok(CallToolResult::error(vec![ContentBlock::text(message)]));
        }

        let aggregated = request.name.as_ref();
        let resolved = self.backends.resolve_tool(aggregated).await;
        let (server, tool) = match resolved {
            Some((server, tool))
                if self
                    .config
                    .read()
                    .await
                    .servers
                    .iter()
                    .any(|s| s.id == server.id && s.exposes(tool.name.as_ref())) =>
            {
                (server, tool)
            }
            _ => {
                return Err(McpError::invalid_params(
                    format!("unknown tool '{aggregated}'"),
                    None,
                ));
            }
        };
        let original_tool = tool.name.to_string();

        let annotations = tool.annotations.map(|a| ToolAnnotations::from(&a));

        let arguments = request
            .arguments
            .clone()
            .map(serde_json::Value::Object)
            .unwrap_or(serde_json::Value::Null);

        let action = policy::Action::from_mcp(
            &agent.id,
            &server.id,
            &original_tool,
            arguments.clone(),
            annotations,
            Utc::now(),
        );

        let mut cancellation = CallAuditGuard {
            audit: &self.audit,
            started,
            entry: Some(AuditEntry {
                id: uuid::Uuid::new_v4().to_string(), at: Utc::now(),
                agent_id: agent.id.clone(), agent_name: agent.name.clone(),
                server_id: server.id.clone(), tool: original_tool.clone(),
                verdict: AuditVerdict::Error, source: AuditSource::Cancelled,
                duration_ms: 0, error: Some("Client cancelled the request; an already-started backend operation may still finish".into()),
                attention: Attention::Silent, native: None, facets: action.facets_summary(),
            }),
        };
        let (mut eval, dnd, on_timeout, rate_limit) = {
            let config = self.config.read().await;
            let eval = policy::evaluate(&config.rules, &agent, &action, Utc::now());
            (
                eval,
                config.do_not_disturb,
                config.on_timeout,
                config.rate_limit_per_minute,
            )
        };

        // The tripwire counts every attempt and turns an allow into an ask once an agent runs hot.
        let tripped = rate_limit.is_some_and(|limit| self.rate_tripped(&agent.id, limit));
        eval.apply_tripwire(tripped);
        let reason = if eval.decider == Decider::Tripwire {
            HoldReason::RateLimit
        } else {
            HoldReason::Policy
        };
        let source = AuditSource::from(&eval.decider);
        // While do-not-disturb is on, nothing louder than a badge gets through.
        let attention = if dnd {
            eval.attention.min(Attention::Badge)
        } else {
            eval.attention
        };

        let result = match eval.verdict {
            Verdict::Allow => {
                self.forward_or_error(
                    &agent,
                    &server,
                    &original_tool,
                    arguments,
                    started,
                    source,
                    AuditVerdict::Allowed,
                    attention,
                    action.facets_summary(),
                )
                .await
            }
            Verdict::Deny => {
                let summary = match &eval.decider {
                    Decider::Rule { rule_id } => {
                        let config = self.config.read().await;
                        config
                            .rules
                            .iter()
                            .find(|r| &r.id == rule_id)
                            .map(rule_summary)
                            .unwrap_or_else(|| "deny".into())
                    }
                    Decider::Posture(p) => format!("{p:?} posture"),
                    Decider::Tripwire => "rate tripwire".into(),
                    Decider::DoNotDisturb => "do not disturb".into(),
                    Decider::Timeout => "timeout".into(),
                };
                let message = format!("Denied by Prism policy: {summary}");
                self.audit.record(AuditEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    at: Utc::now(),
                    agent_id: agent.id,
                    agent_name: agent.name,
                    server_id: server.id,
                    tool: original_tool,
                    verdict: AuditVerdict::Denied,
                    source,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: Some(message.clone()),
                    attention,
                    native: None, facets: action.facets_summary(),
                });
                Ok(CallToolResult::error(vec![ContentBlock::text(message)]))
            }
            Verdict::Ask if dnd => {
                self.resolve_unattended(
                    &agent,
                    &server,
                    &original_tool,
                    arguments,
                    started,
                    &action,
                    on_timeout,
                    AuditSource::from(&Decider::DoNotDisturb),
                    "Prism is in do-not-disturb and this call needed a human. Retry later or ask the operator.",
                )
                .await
            }
            Verdict::Ask => {
                self.hold_then_forward(
                    agent,
                    server,
                    original_tool,
                    arguments,
                    started,
                    &action,
                    reason,
                )
                .await
            }
        };
        cancellation.entry = None;
        result
    }

    /// Nobody can answer (timeout or do-not-disturb): apply the configured fallback.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_unattended(
        &self,
        agent: &AgentConfig,
        server: &ServerConfig,
        tool: &str,
        arguments: serde_json::Value,
        started: Instant,
        action: &policy::Action,
        behavior: TimeoutBehavior,
        source: AuditSource,
        message: &str,
    ) -> std::result::Result<CallToolResult, McpError> {
        let read_only = action
            .annotations
            .as_ref()
            .is_some_and(ToolAnnotations::is_read_only);
        if behavior == TimeoutBehavior::AllowReadOnly && read_only {
            return self
                .forward_or_error(
                    agent,
                    server,
                    tool,
                    arguments,
                    started,
                    source,
                    AuditVerdict::Allowed,
                    Attention::Badge,
                    action.facets_summary(),
                )
                .await;
        }
        let verdict = if source == AuditSource::Timeout {
            AuditVerdict::Timeout
        } else {
            AuditVerdict::Denied
        };
        self.audit.record(AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            at: Utc::now(),
            agent_id: agent.id.clone(),
            agent_name: agent.name.clone(),
            server_id: server.id.clone(),
            tool: tool.to_string(),
            verdict,
            source,
            duration_ms: started.elapsed().as_millis() as u64,
            error: Some(message.to_string()),
            attention: Attention::Badge,
            native: None,
            facets: action.facets_summary(),
        });
        Ok(CallToolResult::error(vec![ContentBlock::text(message)]))
    }

    #[allow(clippy::too_many_arguments)]
    async fn hold_then_forward(
        &self,
        agent: AgentConfig,
        server: ServerConfig,
        tool: String,
        arguments: serde_json::Value,
        started: Instant,
        action: &policy::Action,
        reason: HoldReason,
    ) -> std::result::Result<CallToolResult, McpError> {
        let (hold, on_timeout) = {
            let config = self.config.read().await;
            (
                std::time::Duration::from_secs(config.hold_timeout_secs),
                config.on_timeout,
            )
        };
        let now = Utc::now();
        let pending = PendingCall {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent.id.clone(),
            agent_name: agent.name.clone(),
            server_id: server.id.clone(),
            server_name: server.name.clone(),
            tool: tool.clone(),
            arguments: arguments.clone(),
            facets: action.facets_summary(),
            offers: action.offers(),
            requested_at: now,
            deadline: Some(now + chrono::Duration::from_std(hold).unwrap_or_default()),
            posture: agent.posture,
            reason,
        };
        let _ = self.events.send(GatewayEvent::PendingCall(pending.clone()));
        let mut cleanup = HoldEventGuard {
            events: self.events.clone(),
            id: Some(pending.id.clone()),
        };
        let outcome = self.approval.register_for(pending.clone(), hold).await;
        cleanup.id = None;
        match outcome {
            HoldOutcome::Timeout => {
                self.resolve_unattended(
                    &agent,
                    &server,
                    &tool,
                    arguments,
                    started,
                    action,
                    on_timeout,
                    AuditSource::from(&Decider::Timeout),
                    TIMEOUT_MESSAGE,
                )
                .await
            }
            HoldOutcome::Decided(decision) => match decision.verdict {
                DecisionVerdict::Deny => {
                    self.audit.record(AuditEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        at: Utc::now(),
                        agent_id: agent.id,
                        agent_name: agent.name,
                        server_id: server.id,
                        tool,
                        verdict: AuditVerdict::Denied,
                        source: if reason == HoldReason::RateLimit {
                            AuditSource::from(&Decider::Tripwire)
                        } else {
                            AuditSource::Human
                        },
                        duration_ms: started.elapsed().as_millis() as u64,
                        error: Some("Denied by the user in Prism".into()),
                        attention: Attention::Silent,
                        native: None,
                        facets: action.facets_summary(),
                    });
                    Ok(CallToolResult::error(vec![ContentBlock::text(
                        "Denied by the user in Prism",
                    )]))
                }
                DecisionVerdict::Allow => {
                    self.forward_or_error(
                        &agent,
                        &server,
                        &tool,
                        arguments,
                        started,
                        if reason == HoldReason::RateLimit {
                            AuditSource::from(&Decider::Tripwire)
                        } else {
                            AuditSource::Human
                        },
                        AuditVerdict::Allowed,
                        Attention::Silent,
                        action.facets_summary(),
                    )
                    .await
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_or_error(
        &self,
        agent: &AgentConfig,
        server: &ServerConfig,
        tool: &str,
        arguments: serde_json::Value,
        started: Instant,
        source: AuditSource,
        verdict: AuditVerdict,
        attention: Attention,
        facets: Vec<String>,
    ) -> std::result::Result<CallToolResult, McpError> {
        match self.backends.call_tool(&server.id, tool, arguments).await {
            Ok(result) => {
                let is_err = result.is_error.unwrap_or(false);
                self.audit.record(AuditEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    at: Utc::now(),
                    agent_id: agent.id.clone(),
                    agent_name: agent.name.clone(),
                    server_id: server.id.clone(),
                    tool: tool.to_string(),
                    verdict: if is_err { AuditVerdict::Error } else { verdict },
                    source,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: if is_err {
                        Some("backend tool returned isError".into())
                    } else {
                        None
                    },
                    attention,
                    native: None,
                    facets,
                });
                Ok(result)
            }
            Err(err) => {
                let message = err.to_string();
                self.audit.record(AuditEntry {
                    id: uuid::Uuid::new_v4().to_string(),
                    at: Utc::now(),
                    agent_id: agent.id.clone(),
                    agent_name: agent.name.clone(),
                    server_id: server.id.clone(),
                    tool: tool.to_string(),
                    verdict: AuditVerdict::Error,
                    source,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: Some(message.clone()),
                    attention,
                    native: None,
                    facets,
                });
                Ok(CallToolResult::error(vec![ContentBlock::text(message)]))
            }
        }
    }
}

fn is_hidden(
    hidden: &HashMap<String, std::collections::BTreeSet<String>>,
    server_id: &str,
    tool: &str,
) -> bool {
    hidden.get(server_id).is_some_and(|set| set.contains(tool))
}

/// One MCP session. rmcp builds a fresh proxy per session, so the agent identity learned at
/// `initialize` lives here and is dropped with the session.
struct PrismProxy {
    gateway: Arc<Gateway>,
    session_id: String,
    agent_id: std::sync::Mutex<Option<String>>,
}

impl PrismProxy {
    fn agent_id(&self) -> Option<String> {
        self.agent_id.lock().ok().and_then(|a| a.clone())
    }

    fn request_identity(
        context: &RequestContext<RoleServer>,
    ) -> std::result::Result<AuthenticatedAgent, McpError> {
        context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthenticatedAgent>())
            .cloned()
            .ok_or_else(|| McpError::invalid_request("a bearer token is required", None))
    }

    /// Modern requests carry their own verified identity. Only legacy requests
    /// inherit a session, whose owner must still match the bearer on this request.
    async fn caller(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> std::result::Result<Option<String>, McpError> {
        let identity = Self::request_identity(context)?;
        if context
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
        {
            self.stateless_presence(&identity.agent_id, context).await?;
            return Ok(Some(identity.agent_id));
        }
        let session = self.agent_id();
        if Some(&identity.agent_id) != session.as_ref() {
            return Err(McpError::invalid_request(
                "this session belongs to another agent",
                None,
            ));
        }
        Ok(session)
    }

    async fn stateless_presence(
        &self,
        agent_id: &str,
        context: &RequestContext<RoleServer>,
    ) -> std::result::Result<(), McpError> {
        let client = context.client_info();
        self.gateway
            .register_authenticated_presence(
                &self.session_id,
                agent_id,
                client.as_ref().map(|c| c.version.as_str()),
                None,
            )
            .await
            .ok_or_else(|| McpError::invalid_request("unknown agent", None))?;
        Ok(())
    }
}

impl Drop for PrismProxy {
    fn drop(&mut self) {
        self.gateway.unregister_session(&self.session_id);
    }
}

impl ServerHandler for PrismProxy {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        // Pin the revisions implemented by Prism, rather than implicitly opting
        // into future lifecycle changes whenever the SDK adds another version.
        Cow::Borrowed(&[
            ProtocolVersion::V_2024_11_05,
            ProtocolVersion::V_2025_03_26,
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2026_07_28,
        ])
    }

    async fn discover(
        &self,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<DiscoverResult, McpError> {
        let identity = Self::request_identity(&context)?;
        self.stateless_presence(&identity.agent_id, &context)
            .await?;
        Ok(DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        ))
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Some(requested.intersection(&SubscriptionFilter::builder().tools_list_changed().build()))
    }

    async fn listen(&self, context: SubscriptionContext) -> std::result::Result<(), McpError> {
        let identity = Self::request_identity(context.request_context())?;
        // Subscribe before marking presence so no subsequent change can be missed.
        let mut events = self.gateway.subscribe();
        self.caller(context.request_context()).await?;
        let mut validity = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            let changed = tokio::select! {
                _ = context.cancelled() => break,
                _ = self.gateway.shutdown.cancelled() => break,
                _ = validity.tick() => false,
                event = events.recv() => match event {
                    Ok(GatewayEvent::ServerStatus { .. } | GatewayEvent::ToolsChanged { .. }) => true,
                    Ok(GatewayEvent::AgentDecided { agent_id, .. } | GatewayEvent::AgentUpdated { agent_id }) => agent_id == identity.agent_id,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    _ => false,
                },
            };
            // A notification stream must not outlive its token's authority.
            if self
                .gateway
                .authenticate_hash(&identity.token_hash)
                .await
                .as_deref()
                != Some(identity.agent_id.as_str())
            {
                break;
            }
            if changed && context.accepted().tools_list_changed == Some(true) {
                if context.sink().notify_tool_list_changed().await.is_err() {
                    break;
                }
                self.gateway.mcp_traffic.record(crate::mcp_traffic::McpTransaction {
                    timestamp: Utc::now(),
                    kind: "notification".into(),
                    agent_id: identity.agent_id.clone(),
                    agent_name: self
                        .gateway
                        .agent_by_id(&identity.agent_id)
                        .await
                        .map(|a| a.name)
                        .unwrap_or_else(|| identity.agent_id.clone()),
                    session_id: Some(self.session_id.clone()),
                    id: None,
                    method: "notifications/tools/list_changed".into(),
                    request: None,
                    response: None,
                    duration_ms: None,
                    error: None,
                });
            }
        }
        Ok(())
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("Prism", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Prism local MCP gateway. Tools appear once the human approves this agent in the \
             Prism panel; they are named {server}__{tool}.",
        )
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<InitializeResult, McpError> {
        let started = std::time::Instant::now();
        let authenticated = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<AuthenticatedAgent>())
            .map(|a| a.agent_id.clone());
        let version = Some(request.client_info.version.as_str());
        let res = match authenticated {
            Some(ref auth) => {
                match self
                    .gateway
                    .register_authenticated_presence(
                        &self.session_id,
                        auth,
                        version,
                        Some(context.peer.clone()),
                    )
                    .await
                {
                    Some(agent) => {
                        if let Ok(mut slot) = self.agent_id.lock() {
                            *slot = Some(agent.id.clone());
                        }
                        Ok((agent.id, agent.name, self.get_info()))
                    }
                    None => Err(McpError::invalid_request("unknown agent", None)),
                }
            }
            None => Err(McpError::invalid_request("a bearer token is required", None)),
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        let (agent_id, agent_name, result) = match res {
            Ok((id, name, info)) => (id, name, Ok(info)),
            Err(err) => ("unknown".into(), "unknown".into(), Err(err)),
        };

        self.gateway.mcp_traffic.record(crate::mcp_traffic::McpTransaction {
            timestamp: Utc::now(),
            kind: "transaction".into(),
            agent_id,
            agent_name,
            session_id: Some(self.session_id.clone()),
            id: None,
            method: "initialize".into(),
            request: serde_json::to_value(&request).ok(),
            response: result.as_ref().ok().and_then(|r| serde_json::to_value(r).ok()),
            duration_ms: Some(duration_ms),
            error: result.as_ref().err().map(|e| e.to_string()),
        });

        result
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, McpError> {
        let started = std::time::Instant::now();
        let agent = self.caller(&context).await;
        let (agent_id, agent_name) = match agent.as_ref() {
            Ok(Some(id)) => {
                let name = self
                    .gateway
                    .agent_by_id(id)
                    .await
                    .map(|a| a.name)
                    .unwrap_or_else(|| id.clone());
                (id.clone(), name)
            }
            _ => ("unknown".to_string(), "unknown".to_string()),
        };

        let result = match agent {
            Ok(agent) => {
                let mut result = self.gateway.handle_list_tools(agent.as_deref()).await;
                if context
                    .protocol_version()
                    .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
                {
                    // Tool availability is authorization-dependent and may change at
                    // any time. Supply July's required cache policy without sharing it.
                    result = result
                        .with_ttl_ms(0)
                        .with_cache_scope(rmcp::model::CacheScope::Private);
                }
                Ok(result)
            }
            Err(err) => Err(err),
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        self.gateway.mcp_traffic.record(crate::mcp_traffic::McpTransaction {
            timestamp: Utc::now(),
            kind: "transaction".into(),
            agent_id,
            agent_name,
            session_id: Some(self.session_id.clone()),
            id: None,
            method: "tools/list".into(),
            request: request.and_then(|r| serde_json::to_value(r).ok()),
            response: result.as_ref().ok().and_then(|r| serde_json::to_value(r).ok()),
            duration_ms: Some(duration_ms),
            error: result.as_ref().err().map(|e| e.to_string()),
        });

        result
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, McpError> {
        let started = std::time::Instant::now();
        let agent = self.caller(&context).await;
        let (agent_id, agent_name) = match agent.as_ref() {
            Ok(Some(id)) => {
                let name = self
                    .gateway
                    .agent_by_id(id)
                    .await
                    .map(|a| a.name)
                    .unwrap_or_else(|| id.clone());
                (id.clone(), name)
            }
            _ => ("unknown".to_string(), "unknown".to_string()),
        };

        let req_val = serde_json::to_value(&request).ok();
        let mut resp_val = None;
        let result = match agent {
            Ok(agent) => {
                tokio::select! {
                    biased;
                    _ = context.ct.cancelled() => Err(McpError::invalid_request("request cancelled", None)),
                    result = self.gateway.handle_call_tool(request, agent.as_deref()) => {
                        resp_val = result.as_ref().ok().and_then(|r| serde_json::to_value(r).ok());
                        result.map(|mut result| {
                            // Legacy upstreams omit this field. Restore the modern envelope;
                            // rmcp strips it again when the downstream client is legacy.
                            result.result_type = Some(rmcp::model::ResultType::COMPLETE);
                            result.into()
                        })
                    }
                }
            }
            Err(err) => Err(err),
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        self.gateway.mcp_traffic.record(crate::mcp_traffic::McpTransaction {
            timestamp: Utc::now(),
            kind: "transaction".into(),
            agent_id,
            agent_name,
            session_id: Some(self.session_id.clone()),
            id: None,
            method: "tools/call".into(),
            request: req_val,
            response: resp_val,
            duration_ms: Some(duration_ms),
            error: result.as_ref().err().map(|e| e.to_string()),
        });

        result
    }
}

/// Everything served on the loopback port. `stop` ends this server's sessions when the
/// listener moves; the gateway's own shutdown cancels it too.
fn router(gateway: Arc<Gateway>, stop: CancellationToken) -> Router {
    let gw = gateway.clone();
    let transport_config = StreamableHttpServerConfig::default()
        .disable_allowed_hosts()
        .with_cancellation_token(stop);
    let service: StreamableHttpService<PrismProxy, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(PrismProxy {
                    gateway: gw.clone(),
                    session_id: uuid::Uuid::new_v4().to_string(),
                    agent_id: std::sync::Mutex::new(None),
                })
            },
            LocalSessionManager::default().into(),
            // The outer HTTP guard enforces one Host policy for MCP and OAuth alike.
            transport_config,
        );

    Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn_with_state(
            gateway.clone(),
            oauth::require_bearer,
        ))
        .merge(oauth::router(gateway.clone()))
        .merge(crate::native::router(gateway.clone()))
        .layer(axum::middleware::from_fn_with_state(
            gateway,
            crate::http_security::guard,
        ))
}

impl Gateway {
    /// The port agents dial right now.
    pub fn listen_port(&self) -> u16 {
        self.listener.port()
    }

    /// Where the live server is bound.
    pub fn listen_address(&self) -> ListenAddress {
        self.listener.address()
    }

    /// The MCP URL other machines dial, while exposed and while there is a route out.
    pub fn network_url(&self) -> Option<String> {
        if !self.listener.is_listening() || self.listen_address() != ListenAddress::Network {
            return None;
        }
        let ip = crate::listener::host_ip()?;
        let host = match ip {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        };
        Some(format!("http://{host}:{}/mcp", self.listen_port()))
    }

    /// Bind `port` on `address` and serve on it. On success the previous server, if any, is
    /// stopped and its sessions end; on failure nothing changes, so a move to a busy port
    /// leaves the current one serving.
    async fn bind(
        self: &Arc<Self>,
        address: ListenAddress,
        port: u16,
    ) -> std::result::Result<u16, BindFailure> {
        match self.try_bind(address, port).await {
            Ok(bound) => Ok(bound),
            Err(err) => Err(BindFailure::from_io(port, err).await),
        }
    }

    async fn try_bind(self: &Arc<Self>, address: ListenAddress, port: u16) -> std::io::Result<u16> {
        let listener = tokio::net::TcpListener::bind(socket(address, port)).await?;
        let bound = listener.local_addr()?.port();
        let stop = self.shutdown.child_token();
        let app = router(self.clone(), stop.clone());
        let shutdown = stop.clone();
        let task = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    shutdown.cancelled().await;
                })
                .await
            {
                warn!(%err, "gateway http server exited");
            }
        });
        self.listener.adopt(address, bound, Serving { stop, task });
        Ok(bound)
    }

    /// Bind once the previous server on the same port has let go of it. The OS refuses
    /// `0.0.0.0:P` while `127.0.0.1:P` is bound and the other way round, so an address change
    /// cannot bind first; it stops, then binds, and waits for the port to come free.
    async fn bind_after_release(
        self: &Arc<Self>,
        address: ListenAddress,
        port: u16,
    ) -> std::result::Result<u16, BindFailure> {
        if let Some(previous) = self.listener.release() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), previous.task).await;
        }
        let mut attempt = 0;
        loop {
            match self.try_bind(address, port).await {
                Ok(bound) => return Ok(bound),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse && attempt < 20 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(err) => return Err(BindFailure::from_io(port, err).await),
            }
        }
    }

    /// Try the configured port again after a clash. A no-op while listening.
    pub async fn retry_listener(self: &Arc<Self>) -> Result<()> {
        if self.listener.is_listening() {
            return Ok(());
        }
        let (address, port) = {
            let config = self.config.read().await;
            (config.listen_address, config.listen_port)
        };
        let outcome = self.bind(address, port).await;
        if let Err(failure) = &outcome {
            self.listener.set_state(failure.state(port));
        }
        let _ = self.events.send(GatewayEvent::ListenerChanged);
        outcome
            .map(|_| ())
            .map_err(|failure| Error::Invalid(failure.message(port)))
    }

    /// A free port near the configured one, for the panel to offer. Never chosen on Prism's
    /// own: every connected agent dials the configured port, so moving is the operator's call.
    pub async fn suggest_port(&self) -> Option<u16> {
        let from = self.config.read().await.listen_port;
        tokio::task::spawn_blocking(move || crate::listener::suggest_port(from))
            .await
            .ok()
            .flatten()
    }

    /// Move the listener to `port` and remember it. The new port is bound before the old one
    /// stops, so a refused port changes nothing. Agents keep their tokens; they need the new
    /// address.
    pub async fn set_listen_port(self: &Arc<Self>, port: u16) -> Result<()> {
        if port == 0 {
            return Err(Error::Invalid("Choose a port between 1 and 65535".into()));
        }
        let address = {
            let config = self.config.read().await;
            if port == config.listen_port && self.listener.is_listening() {
                return Ok(());
            }
            config.listen_address
        };
        self.bind(address, port)
            .await
            .map_err(|failure| Error::Invalid(failure.message(port)))?;
        {
            let mut config = self.config.write().await;
            config.listen_port = port;
            config.save(&self.config_path)?;
        }
        info!(port, "gateway listener moved");
        let _ = self.events.send(GatewayEvent::ListenerChanged);
        Ok(())
    }

    /// Bind the configured port on loopback only or on every interface, and remember it.
    /// Same rule as a port move: the new server is up before the old one stops.
    pub async fn set_listen_address(self: &Arc<Self>, address: ListenAddress) -> Result<()> {
        let previous = self.config.read().await.listen_address;
        if address == previous && self.listener.is_listening() {
            return Ok(());
        }
        // The port agents dial today, which is the configured one except when the OS chose it.
        let port = self.listen_port();
        if let Err(failure) = self.bind_after_release(address, port).await {
            // Put the old server back so a refused change leaves things as they were.
            if let Err(back) = self.bind_after_release(previous, port).await {
                self.listener.set_state(back.state(port));
            }
            let _ = self.events.send(GatewayEvent::ListenerChanged);
            return Err(Error::Invalid(failure.message(port)));
        }
        {
            let mut config = self.config.write().await;
            config.listen_address = address;
            config.save(&self.config_path)?;
        }
        info!(address = %address.ip(), port, "gateway listener rebound");
        let _ = self.events.send(GatewayEvent::ListenerChanged);
        Ok(())
    }
}

fn aggregate_tool(server_name: &str, mut tool: Tool) -> Tool {
    tool.name = format!("{server_name}__{}", tool.name).into();
    tool
}

fn rule_summary(rule: &Rule) -> String {
    let agent = rule.agent_id.as_deref().unwrap_or("*");
    let server = rule.server_id.as_deref().unwrap_or("*");
    let tool = rule.tool.as_deref().unwrap_or("*");
    let decision = match rule.decision {
        RuleDecision::Allow => "allow",
        RuleDecision::Deny => "deny",
        RuleDecision::Ask => "ask",
    };
    format!("{decision} agent={agent} server={server} tool={tool}")
}

fn host_display_name(host: &str) -> String {
    crate::native::harness_display_name(host).to_string()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The hook secret persists so the URL in the host's settings keeps working across restarts.
fn load_or_create_hook_token(path: &Path) -> Result<String> {
    if path.exists() {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut crate::storage::read(path)?, &mut text)?;
        let token = text.trim().to_string();
        if token.len() >= 32 {
            return Ok(token);
        }
    }
    let token = crate::native::new_token();
    crate::storage::atomic_write(path, token.as_bytes())?;
    Ok(token)
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod listener_tests;

#[cfg(test)]
#[path = "native/http_tests.rs"]
mod native_http_tests;

#[cfg(test)]
mod agent_removal_tests {
    use super::*;

    #[tokio::test]
    async fn removing_an_agent_removes_only_its_rules_and_persists_the_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prism.json");
        PrismConfig {
            listen_port: 0,
            ..Default::default()
        }
        .save(&path)
        .unwrap();
        let gateway = Gateway::start_with_credentials(
            path.clone(),
            dir.path().join("audit.jsonl"),
            Arc::new(crate::credentials::tests::MemoryStore::default()),
        )
        .await
        .unwrap();
        gateway.ensure_host_agent("goose").await.unwrap();
        gateway.ensure_host_agent("codex").await.unwrap();
        let mut kept_ids = Vec::new();
        for agent_id in [Some("host:goose"), Some("host:codex"), None] {
            let rule = gateway
                .add_rule(NewRule {
                    agent_id: agent_id.map(str::to_string),
                    server_id: None,
                    tool: Some("read_file".into()),
                    decision: RuleDecision::Allow,
                    attention: None,
                    scope: RuleScope::Always,
                    minutes: None,
                })
                .await
                .unwrap();
            if agent_id != Some("host:goose") {
                kept_ids.push(rule.id);
            }
        }
        assert_eq!(gateway.rules().await.len(), 3);
        assert_eq!(PrismConfig::load(&path).unwrap().rules.len(), 3);
        let mut events = gateway.subscribe();

        gateway.remove_agent("host:goose").await.unwrap();

        let saved = PrismConfig::load(&path).unwrap();
        assert!(saved.agents.iter().all(|a| a.id != "host:goose"));
        for rules in [gateway.rules().await, saved.rules] {
            assert!(rules
                .iter()
                .all(|r| r.agent_id.as_deref() != Some("host:goose")));
            assert_eq!(
                rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
                kept_ids
            );
        }
        let mut rules_changed = false;
        while let Ok(event) = events.try_recv() {
            rules_changed |= matches!(event, GatewayEvent::RulesChanged);
        }
        assert!(rules_changed);
        gateway.shutdown().await;
    }
}

#[cfg(test)]
mod retained_history_tests {
    use super::*;
    use crate::audit::{AuditQuery, NativeDetail};

    pub(super) fn gateway(path: &Path) -> Gateway {
        let (events, _) = channel();
        let credentials = Arc::new(crate::credentials::NativeStore::default());
        let mcp_traffic = Arc::new(
            crate::mcp_traffic::McpTrafficLogger::new(path.with_file_name("mcp.jsonl")).unwrap(),
        );
        Gateway {
            config_path: path.with_extension("config"),
            config: RwLock::new(PrismConfig::default()),
            backends: BackendManager::new(events.clone(), credentials.clone()),
            credentials,
            approval: ApprovalRegistry::new(),
            audit: AuditLog::new(path, events.clone()).unwrap(),
            mcp_traffic,
            events,
            shutdown: CancellationToken::new(),
            listener: Listener::idle(0),
            oauth: OAuthState::default(),
            sessions: std::sync::Mutex::new(HashMap::new()),
            calls: std::sync::Mutex::new(HashMap::new()),
            native_budget: std::sync::Mutex::new(Default::default()),
            native_last: std::sync::Mutex::new(HashMap::new()),
            hook_token: std::sync::RwLock::new("test-token".into()),
            hook_token_path: path.with_extension("hook-token"),
        }
    }

    fn native(
        at: chrono::DateTime<Utc>,
        id: &str,
        host: &str,
        reason: Option<&str>,
        duplicate: bool,
    ) -> AuditEntry {
        AuditEntry {
            id: id.into(),
            at,
            agent_id: format!("legacy-{host}"),
            agent_name: crate::native::harness_display_name(host).into(),
            server_id: host.into(),
            tool: "shell".into(),
            verdict: AuditVerdict::Allowed,
            source: AuditSource::Observed,
            duration_ms: 0,
            error: None,
            attention: Attention::Silent,
            facets: Vec::new(),
            native: Some(NativeDetail {
                host: host.into(),
                session: None,
                cwd: None,
                subject: "ls".into(),
                would_hold: reason.map(str::to_string),
                agent_type: None,
                via_prism: duplicate,
            }),
        }
    }

    #[tokio::test]
    async fn hiding_a_tool_persists_and_keeps_it_from_agents() {
        let dir = tempfile::tempdir().unwrap();
        let gw = gateway(&dir.path().join("audit.jsonl"));
        {
            let mut config = gw.config.write().await;
            config.servers.push(ServerConfig {
                id: "srv".into(),
                name: "files".into(),
                command: "true".into(),
                args: Vec::new(),
                env: Default::default(),
                credential_ref: None,
                enabled: true,
                url: None,
                auth: HttpAuth::None,
                headers: Default::default(),
                oauth_ref: None,
                hidden_tools: Default::default(),
            });
        }
        assert!(gw.set_tool_exposed("missing", "x", false).await.is_err());
        gw.set_tool_exposed("srv", "delete_file", false)
            .await
            .unwrap();
        let hidden = gw.hidden_tools().await;
        assert!(is_hidden(&hidden, "srv", "delete_file"));
        assert!(!is_hidden(&hidden, "srv", "read_file"));
        assert!(!is_hidden(&hidden, "other", "delete_file"));
        let saved = PrismConfig::load(&gw.config_path).unwrap();
        assert!(!saved.servers[0].exposes("delete_file"));
        gw.set_tool_exposed("srv", "delete_file", true)
            .await
            .unwrap();
        assert!(gw.hidden_tools().await.is_empty());
        assert!(PrismConfig::load(&gw.config_path).unwrap().servers[0].exposes("delete_file"));
    }

    #[tokio::test]
    async fn setup_lists_a_harness_once_and_never_revives_a_refused_one() {
        let dir = tempfile::tempdir().unwrap();
        let gw = gateway(&dir.path().join("audit.jsonl"));
        assert!(gw.ensure_host_agent("not-a-harness").await.is_err());
        gw.ensure_host_agent("goose").await.unwrap();
        gw.ensure_host_agent("goose").await.unwrap();
        let listed: Vec<_> = gw
            .agents()
            .await
            .into_iter()
            .filter(|a| a.agent.id == "host:goose")
            .collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].agent.status, AgentStatus::Approved);
        gw.decide_agent("host:goose", false).await.unwrap();
        gw.ensure_host_agent("goose").await.unwrap();
        let agent = gw
            .agents()
            .await
            .into_iter()
            .find(|a| a.agent.id == "host:goose")
            .unwrap();
        assert_eq!(agent.agent.status, AgentStatus::Denied);
    }

    #[tokio::test]
    async fn native_host_reason_counts_match_frozen_drilldowns_and_retained_exports() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let at = Utc::now() - chrono::Duration::minutes(1);
        let rows = [
            native(at, "claude-hit", "claude-code", Some("sudo"), false),
            native(at, "claude-other", "claude-code", Some("rm"), false),
            native(at, "claude-routine", "claude-code", None, false),
            native(at, "codex-hit", "codex", Some("sudo"), false),
            native(at, "codex-hit2", "codex", Some("sudo"), false),
            native(at, "duplicate", "codex", Some("sudo"), true),
            native(
                at - chrono::Duration::days(10),
                "archived-old",
                "codex",
                Some("sudo"),
                false,
            ),
        ];
        // All rows live in a rotated file; the active file starts empty.
        std::fs::write(
            path.with_file_name("audit.jsonl.1"),
            rows.iter()
                .map(|row| format!("{}\n", serde_json::to_string(row).unwrap()))
                .collect::<String>(),
        )
        .unwrap();
        let gateway = gateway(&path);
        let status = gateway.native_status().await.unwrap();
        assert_eq!(status.actions_7d, 5);
        assert_eq!(status.would_hold_7d, 4);
        for host in &status.hosts {
            let query = AuditQuery {
                at: Some(status.window.snapshot_at),
                agent_id: Some(format!("host:{}", host.host)),
                native_only: true,
                ..Default::default()
            };
            assert_eq!(
                gateway.audit_query(query.clone()).await.unwrap().total,
                host.actions_7d
            );
            for reason in &host.by_reason {
                assert_eq!(
                    gateway
                        .audit_query(AuditQuery {
                            reason: Some(reason.reason.clone()),
                            ..query.clone()
                        })
                        .await
                        .unwrap()
                        .total,
                    reason.count
                );
            }
        }
        let claude = status
            .hosts
            .iter()
            .find(|host| host.host == "claude-code")
            .unwrap();
        let codex = status
            .hosts
            .iter()
            .find(|host| host.host == "codex")
            .unwrap();
        assert_eq!(
            claude
                .by_reason
                .iter()
                .find(|reason| reason.reason == "sudo")
                .unwrap()
                .count,
            1
        );
        assert_eq!(codex.by_reason[0].count, 2);
        let summary = gateway.activity(7).await.unwrap();
        assert_eq!(summary.total, status.actions_7d);
        assert_eq!(summary.attention, status.would_hold_7d);
        let export = gateway.native_export(30).await.unwrap();
        assert_eq!(export.lines().count(), 5);
        assert!(export.contains("archived-old"));
        assert!(!export.contains("duplicate"));
        assert!(!export.contains("claude-routine"));
        let with_metadata = gateway
            .audit_export(AuditQuery {
                days: 30,
                native_only: true,
                attention: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(with_metadata.jsonl, export);
        assert_eq!(with_metadata.total, 5);
        assert!(!with_metadata.window.full_window_guaranteed);
        gateway.audit.close();
        std::fs::remove_file(&path).unwrap();
        assert!(gateway.activity(7).await.is_err());
        assert!(gateway.native_status().await.is_err());
        assert!(gateway.native_export(30).await.is_err());
        assert!(gateway.audit_export(AuditQuery::default()).await.is_err());
    }

    #[tokio::test]
    async fn manual_agents_named_codex_or_claude_keep_their_authenticated_audit_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let gateway = gateway(&path);
        let codex = gateway.create_manual_agent("Codex").await.unwrap();
        let claude = gateway.create_manual_agent("Claude Code").await.unwrap();
        let at = Utc::now() - chrono::Duration::seconds(1);
        for (id, name) in [
            (&codex.agent_id, "Codex"),
            (&claude.agent_id, "Claude Code"),
        ] {
            let mut row = native(at, id, "codex", None, false);
            row.agent_id = id.clone();
            row.agent_name = name.into();
            row.native = None;
            row.source = AuditSource::Human;
            gateway.audit.record(row);
        }
        let mut legacy = native(at, "legacy-row", "codex", None, false);
        legacy.agent_id = "historical-oauth-registration".into();
        legacy.native = None;
        gateway.audit.record(legacy);
        let summary = gateway.activity(7).await.unwrap();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.agents.len(), 3);
        for id in [&codex.agent_id, &claude.agent_id] {
            let agent = summary.agents.iter().find(|agent| &agent.id == id).unwrap();
            assert_eq!(agent.total, 1);
            assert!(!agent.host);
            let query = AuditQuery {
                at: Some(summary.window.snapshot_at),
                agent_id: Some(id.clone()),
                ..Default::default()
            };
            let page = gateway.audit_query(query.clone()).await.unwrap();
            assert_eq!(page.total, 1);
            assert_eq!(&page.entries[0].agent_id, id);
            let exported = gateway.audit_export(query).await.unwrap();
            assert_eq!(exported.total, 1);
            let row: AuditEntry = serde_json::from_str(exported.jsonl.trim()).unwrap();
            assert_eq!(&row.agent_id, id);
        }
        let host = gateway
            .audit_query(AuditQuery {
                agent_id: Some("host:codex".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(host.total, 1);
        assert_eq!(host.entries[0].agent_id, "historical-oauth-registration");
        assert_eq!(
            gateway
                .audit_query(AuditQuery {
                    agent_id: Some("host:claude-code".into()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .total,
            0
        );
        let raw: Vec<AuditEntry> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(raw.iter().any(|entry| entry.agent_id == codex.agent_id));
        assert!(raw.iter().any(|entry| entry.agent_id == claude.agent_id));
        assert!(raw
            .iter()
            .any(|entry| entry.agent_id == "historical-oauth-registration"));
        gateway.audit.close();
    }
}
