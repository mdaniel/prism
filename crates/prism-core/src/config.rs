use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A user-configured MCP server: a stdio command Prism spawns, or a remote Streamable HTTP URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub id: String,
    pub name: String,
    /// Executable for a stdio server. Empty for a remote one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// OS credential-store reference for argument, environment and header values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Streamable HTTP endpoint of a remote server. When set, `command` is unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// How a remote server is authenticated.
    #[serde(default, skip_serializing_if = "HttpAuth::is_none")]
    pub auth: HttpAuth,
    /// Extra request headers for a remote server, such as an API key. Plaintext only
    /// until protected; then they live in the credential store like `env`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Credential-store reference for the OAuth client registration and tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_ref: Option<String>,
    /// Tools the panel keeps from every agent: not listed, and refused as unknown if called.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub hidden_tools: BTreeSet<String>,
    /// Subprocess hook command to intercept and patch MCP messages for this server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<ServerHookConfig>,
}

/// Direction of MCP JSON-RPC traffic to intercept.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookDirection {
    #[default]
    Send,
    Recv,
    Both,
}

impl HookDirection {
    pub fn intercepts_send(&self) -> bool {
        matches!(self, HookDirection::Send | HookDirection::Both)
    }

    pub fn intercepts_recv(&self) -> bool {
        matches!(self, HookDirection::Recv | HookDirection::Both)
    }
}

fn default_hook_direction() -> HookDirection {
    HookDirection::Send
}

fn default_hook_timeout() -> u64 {
    10
}

/// A subprocess hook that intercepts and can patch raw MCP JSON-RPC messages for an upstream server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHookConfig {
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default = "default_hook_direction")]
    pub direction: HookDirection,
    #[serde(default = "default_hook_timeout")]
    pub timeout_secs: u64,
}

impl ServerConfig {
    pub fn is_remote(&self) -> bool {
        self.url.is_some()
    }

    /// Whether agents may see and call `tool` on this server.
    pub fn exposes(&self, tool: &str) -> bool {
        !self.hidden_tools.contains(tool)
    }
}

/// Authentication for a remote server. Secrets never sit in `prism.json`: a header value is
/// kept in the credential store, and OAuth tokens under `oauth_ref`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuth {
    #[default]
    None,
    /// A fixed header on every request, typically `Authorization: Bearer <key>`.
    Header,
    /// OAuth 2.1 with dynamic client registration and PKCE; Prism signs in through the browser.
    Oauth,
}

impl HttpAuth {
    pub fn is_none(&self) -> bool {
        matches!(self, HttpAuth::None)
    }
}

/// Whether an agent may see and call tools. New agents start pending until a human decides.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Pending,
    Approved,
    Denied,
}

/// The default an agent starts from when no rule matches one of its calls.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// Every call asks.
    Supervised,
    /// Every call asks until a rule exists for that tool; the panel offers to remember the answer.
    #[default]
    FirstUse,
    /// Tools the server marks read-only pass silently; everything else asks. Trusts the server's
    /// own annotations, which is fine for servers the operator installed.
    Guided,
    /// Everything passes and is logged.
    Trusted,
}

/// How loudly Prism tells the operator about a call it resolved without asking.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    #[default]
    Silent,
    /// Flip the tray icon until the panel is next opened.
    Badge,
    /// Badge plus an OS notification.
    Notify,
    /// Notify plus open the panel.
    Open,
}

/// An agent identified by an OAuth or manually issued bearer token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default = "AgentStatus::approved")]
    pub status: AgentStatus,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    /// What happens to a call no rule covers.
    #[serde(default)]
    pub posture: Posture,
    /// How calls resolved without asking are surfaced. Rules may override it.
    #[serde(default)]
    pub attention: Attention,
    /// The OAuth client this agent signs in as; absent for manually configured agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Set for an agent host observed through its hooks (`claude-code`). Such agents never hold
    /// a token or an MCP session; their record exists for the coverage label and the feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// An OAuth client registered dynamically (RFC 7591). Registration is open; it grants
/// nothing until the operator approves the agent that signs in with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// The agent this client signs in as. Several clients can share one agent: every copy of a
    /// harness on this machine, whatever scope it registered from, is one agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Where the registration came from. `None` is this machine. Set once the gateway accepts
    /// remote clients, so a harness on another host is a separate agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Access,
    Refresh,
    Manual,
}

/// One issued token, stored only as a SHA-256 hash. The clear text is seen once, by the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub hash: String,
    pub kind: TokenKind,
    pub agent_id: String,
    pub client_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl TokenRecord {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expiry) => expiry <= now,
            None => self.kind != TokenKind::Manual,
        }
    }
}

impl AgentStatus {
    /// Agents written by earlier versions were created by hand, so treat them as approved.
    fn approved() -> Self {
        AgentStatus::Approved
    }
}

impl AgentConfig {
    pub fn is_approved(&self) -> bool {
        self.status == AgentStatus::Approved
    }

    /// The record for a harness such as Claude Code: one per harness per origin, shared by its
    /// hooks and every MCP client it registers.
    pub fn harness(
        host: &str,
        origin: Option<&str>,
        status: AgentStatus,
        now: DateTime<Utc>,
    ) -> Self {
        let display = crate::native::harness_display_name(host);
        let name = match origin {
            Some(origin) if !origin.is_empty() => format!("{display} on {origin}"),
            _ => display.to_string(),
        };
        AgentConfig {
            id: crate::native::harness_agent_id(host, origin),
            name,
            client_name: host.to_string(),
            client_version: None,
            status,
            created_at: now,
            decided_at: (status != AgentStatus::Pending).then_some(now),
            posture: Posture::default(),
            attention: Attention::default(),
            client_id: None,
            host: Some(host.to_string()),
        }
    }
}

/// What a rule does with a matching tool call. `Ask` is an explicit override, for example one
/// tool that should always be confirmed under an otherwise trusted agent.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    Allow,
    Deny,
    Ask,
}

/// How long a rule lasts. Session-scoped rules are never written to disk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleScope {
    Session,
    Always,
}

/// A policy rule matching some combination of agent, server, and tool.
///
/// Decision, attention, and duration are independent: a rule can allow silently, allow and
/// notify, deny and open the panel, and any of those for thirty minutes or forever.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub agent_id: Option<String>,
    pub server_id: Option<String>,
    /// Exact tool name, or a glob with `*` such as `create_*`. `None` matches every tool.
    pub tool: Option<String>,
    pub decision: RuleDecision,
    /// `None` inherits the agent's attention.
    #[serde(default)]
    pub attention: Option<Attention>,
    pub scope: RuleScope,
    /// Time-boxed grants expire on their own and are pruned when seen.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Argument-level conditions, retained as JSON even when invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<serde_json::Value>,
    #[serde(default, skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub condition_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Rule {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|t| t <= now)
    }

    pub fn tool_is_glob(&self) -> bool {
        self.tool.as_deref().is_some_and(|t| t.contains('*'))
    }
}

/// What a held call becomes when nobody answers, or when do-not-disturb is on.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutBehavior {
    #[default]
    Deny,
    /// Let it through if the server marks the tool read-only, otherwise deny.
    AllowReadOnly,
}

/// On-disk (and in-memory) Prism configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrismConfig {
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Where the listener binds. Loopback is this machine only; network is every interface.
    #[serde(default)]
    pub listen_address: ListenAddress,
    #[serde(default = "default_true")]
    pub auto_open_on_pending: bool,
    /// Where the panel opens. `auto` infers the tray edge from the monitor's work area.
    #[serde(default)]
    pub panel_anchor: PanelAnchor,
    /// The global key that toggles the panel, in `Ctrl+Alt+P` form. Unset means the default;
    /// an empty string turns the shortcut off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panel_shortcut: Option<String>,
    /// What a held call becomes when nobody answers in time.
    #[serde(default)]
    pub on_timeout: TimeoutBehavior,
    /// While on, asks resolve by `on_timeout` immediately and attention is capped at a badge.
    /// Agent connection requests still come through.
    #[serde(default)]
    pub do_not_disturb: bool,
    /// Tripwire: above this many calls per minute from one agent, allows become asks.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    /// How long a held call waits for a human.
    #[serde(default = "default_hold_timeout_secs")]
    pub hold_timeout_secs: u64,
    /// Record native actions reported by agent hosts' hooks. Off keeps the hook route answering
    /// but writes nothing.
    #[serde(default = "default_true")]
    pub observe_native: bool,
    #[serde(default)]
    pub clients: Vec<OAuthClient>,
    #[serde(default)]
    pub tokens: Vec<TokenRecord>,
}

/// Screen corner the panel anchors to. Tray icons sit at the right end of a top or bottom
/// panel on most desktops; `auto` reads the panel's reserved strut and picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PanelAnchor {
    #[default]
    Auto,
    TopRight,
    TopLeft,
    BottomRight,
    BottomLeft,
}

impl Default for PrismConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            agents: Vec::new(),
            rules: Vec::new(),
            listen_port: default_listen_port(),
            listen_address: ListenAddress::Loopback,
            auto_open_on_pending: true,
            panel_anchor: PanelAnchor::Auto,
            panel_shortcut: None,
            on_timeout: TimeoutBehavior::Deny,
            do_not_disturb: false,
            rate_limit_per_minute: None,
            hold_timeout_secs: default_hold_timeout_secs(),
            observe_native: true,
            clients: Vec::new(),
            tokens: Vec::new(),
        }
    }
}

impl PrismConfig {
    /// Load pretty JSON from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let mut config: Self = serde_json::from_reader(crate::storage::read(path.as_ref())?)
            .map_err(|err: serde_json::Error| {
                crate::error::Error::Invalid(format!(
                    "invalid configuration JSON at line {}, column {}",
                    err.line(),
                    err.column()
                ))
            })?;
        for agent in &mut config.agents {
            if agent.client_name.is_empty() {
                agent.client_name = agent.name.clone();
            }
        }
        config.merge_harness_agents();
        Ok(config)
    }

    /// Write pretty JSON to `path`. Session-scoped rules are never persisted.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        if self
            .servers
            .iter()
            .any(|s| !s.args.is_empty() || !s.env.is_empty())
        {
            return Err(crate::error::Error::Invalid(
                "server launch values must be moved to OS credential storage before saving".into(),
            ));
        }
        let mut to_save = self.clone();
        let now = Utc::now();
        to_save
            .rules
            .retain(|rule| rule.scope == RuleScope::Always && !rule.is_expired(now));
        to_save.tokens.retain(|token| !token.is_expired(now));
        let data = serde_json::to_string_pretty(&to_save)?;
        crate::storage::atomic_write(path.as_ref(), data.as_bytes())?;
        Ok(())
    }
}

impl PrismConfig {
    /// The agent an OAuth client signs in as, if it is bound to one.
    pub fn client_agent_id(&self, client_id: &str) -> Option<String> {
        if let Some(bound) = self
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .and_then(|c| c.agent_id.clone())
        {
            return Some(bound);
        }
        self.agents
            .iter()
            .find(|a| a.client_id.as_deref() == Some(client_id))
            .map(|a| a.id.clone())
    }

    /// Every OAuth client bound to an agent. Empty for manual agents and hook-only harnesses.
    pub fn agent_client_ids(&self, agent_id: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .clients
            .iter()
            .filter(|c| c.agent_id.as_deref() == Some(agent_id))
            .map(|c| c.client_id.clone())
            .collect();
        if let Some(legacy) = self
            .agents
            .iter()
            .find(|a| a.id == agent_id)
            .and_then(|a| a.client_id.clone())
        {
            if !ids.contains(&legacy) {
                ids.push(legacy);
            }
        }
        ids
    }

    /// Bind a client to an agent record.
    fn bind_client(&mut self, client_id: &str, agent_id: &str) {
        if let Some(client) = self.clients.iter_mut().find(|c| c.client_id == client_id) {
            client.agent_id = Some(agent_id.to_string());
        }
    }

    /// The agent bound to an OAuth client, or the agent it should be bound to. A client that
    /// names a known harness joins that harness's record on this machine, so three Claude Code
    /// registrations (user scope, two projects) are one agent with one posture and one rule
    /// set; each new client still gets its own sign-in consent. Anything else is a new pending
    /// agent named after the client, since a public client id proves nothing by itself.
    pub fn find_or_request_agent_for_client(
        &mut self,
        client: &OAuthClient,
    ) -> (AgentConfig, bool) {
        if let Some(id) = self.client_agent_id(&client.client_id) {
            if let Some(agent) = self.agents.iter().find(|a| a.id == id) {
                return (agent.clone(), false);
            }
        }
        if let Some(host) = crate::native::harness_for_client_name(&client.client_name) {
            let id = crate::native::harness_agent_id(host, client.origin.as_deref());
            let first_client = !self
                .clients
                .iter()
                .any(|c| c.agent_id.as_deref() == Some(id.as_str()));
            let created = match self.agents.iter_mut().find(|a| a.id == id) {
                Some(agent) => {
                    // A record the hooks made carries the observe-only default. Its first MCP
                    // client is where posture starts to matter, so start it where new agents start.
                    if first_client && agent.posture == Posture::Trusted {
                        agent.posture = Posture::default();
                    }
                    false
                }
                None => {
                    self.agents.push(AgentConfig::harness(
                        host,
                        client.origin.as_deref(),
                        AgentStatus::Pending,
                        Utc::now(),
                    ));
                    true
                }
            };
            self.bind_client(&client.client_id, &id);
            let agent = self
                .agents
                .iter()
                .find(|a| a.id == id)
                .cloned()
                .expect("harness agent exists");
            return (agent, created);
        }
        let base = client.client_name.trim();
        let base = if base.is_empty() { "unknown" } else { base };
        let mut name = base.to_string();
        let mut n = 2;
        while self
            .agents
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(&name))
        {
            name = format!("{base} ({n})");
            n += 1;
        }
        let agent = AgentConfig {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            client_name: base.to_string(),
            client_version: None,
            status: AgentStatus::Pending,
            created_at: Utc::now(),
            decided_at: None,
            posture: Posture::default(),
            attention: Attention::default(),
            client_id: Some(client.client_id.clone()),
            host: None,
        };
        self.agents.push(agent.clone());
        self.bind_client(&client.client_id, &agent.id);
        (agent, true)
    }

    /// Fold agents that earlier versions made per client registration into their harness's
    /// record, and stamp the binding on every client. Runs at load; returns whether anything moved.
    pub fn merge_harness_agents(&mut self) -> bool {
        let mut changed = false;
        // Harness records written before the host field existed carry only the id.
        for agent in &mut self.agents {
            if agent.host.is_none() {
                if let Some(rest) = agent.id.strip_prefix("host:") {
                    let host = rest.split('@').next().unwrap_or(rest);
                    if !host.is_empty() {
                        agent.host = Some(host.to_string());
                        changed = true;
                    }
                }
            }
        }
        for agent in &self.agents {
            if let Some(client_id) = &agent.client_id {
                if let Some(client) = self.clients.iter().find(|c| &c.client_id == client_id) {
                    if client.agent_id.is_none() {
                        changed = true;
                    }
                }
            }
        }
        let legacy: Vec<AgentConfig> = self
            .agents
            .iter()
            .filter(|a| a.host.is_none())
            .filter(|a| a.client_id.is_some())
            .filter(|a| crate::native::harness_for_client_name(&a.client_name).is_some())
            .cloned()
            .collect();
        for agent in legacy {
            let host =
                crate::native::harness_for_client_name(&agent.client_name).expect("filtered above");
            let target_id = crate::native::harness_agent_id(host, None);
            let client_id = agent.client_id.clone().expect("filtered above");
            match self.agents.iter_mut().find(|a| a.id == target_id) {
                Some(target) => {
                    // The hooks' record never governed a call; the MCP agent's settings did.
                    if target.posture == Posture::Trusted && target.client_id.is_none() {
                        target.posture = agent.posture;
                        target.attention = agent.attention;
                    }
                    if target.client_version.is_none() {
                        target.client_version = agent.client_version.clone();
                    }
                }
                None => {
                    let mut moved =
                        AgentConfig::harness(host, None, agent.status, agent.created_at);
                    moved.decided_at = agent.decided_at;
                    moved.posture = agent.posture;
                    moved.attention = agent.attention;
                    moved.client_version = agent.client_version.clone();
                    self.agents.push(moved);
                }
            }
            for token in &mut self.tokens {
                if token.agent_id == agent.id {
                    token.agent_id = target_id.clone();
                }
            }
            for rule in &mut self.rules {
                if rule.agent_id.as_deref() == Some(agent.id.as_str()) {
                    rule.agent_id = Some(target_id.clone());
                }
            }
            self.bind_client(&client_id, &target_id);
            self.agents.retain(|a| a.id != agent.id);
            changed = true;
        }
        // Every client carries its binding from here on; the agent's own client_id is legacy.
        let bindings: Vec<(String, String)> = self
            .agents
            .iter()
            .filter_map(|a| a.client_id.clone().map(|c| (c, a.id.clone())))
            .collect();
        for (client_id, agent_id) in bindings {
            self.bind_client(&client_id, &agent_id);
        }
        changed
    }
}

fn default_hold_timeout_secs() -> u64 {
    120
}

fn default_listen_port() -> u16 {
    9086
}

/// Which interfaces the gateway listens on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListenAddress {
    /// 127.0.0.1: agents on this machine only.
    #[default]
    Loopback,
    /// 0.0.0.0: every interface, so agents elsewhere on the network can connect too.
    Network,
}

impl ListenAddress {
    pub fn ip(self) -> std::net::IpAddr {
        match self {
            Self::Loopback => std::net::Ipv4Addr::LOCALHOST.into(),
            Self::Network => std::net::Ipv4Addr::UNSPECIFIED.into(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn config_round_trip_drops_session_rules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("prism.json");
        let created = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();

        let original = PrismConfig {
            listen_port: 9099,
            listen_address: ListenAddress::Network,
            auto_open_on_pending: false,
            observe_native: true,
            panel_anchor: PanelAnchor::BottomLeft,
            panel_shortcut: Some("Ctrl+Alt+P".into()),
            servers: vec![ServerConfig {
                id: "srv-1".into(),
                name: "files".into(),
                command: "npx".into(),
                args: Vec::new(),
                env: BTreeMap::new(),
                credential_ref: Some(uuid::Uuid::new_v4().to_string()),
                url: None,
                auth: HttpAuth::None,
                headers: Default::default(),
                oauth_ref: None,
                hidden_tools: ["delete_file".to_string()].into_iter().collect(),
                hook: None,
                enabled: true,
            }],
            agents: vec![AgentConfig {
                id: "agt-1".into(),
                name: "claude".into(),
                client_name: "claude-code".into(),
                client_version: Some("2.0".into()),
                status: AgentStatus::Approved,
                decided_at: None,
                created_at: created,
                posture: Posture::Guided,
                attention: Attention::Notify,
                client_id: None,
                host: None,
            }],
            rules: vec![
                Rule {
                    id: "rule-always".into(),
                    agent_id: Some("agt-1".into()),
                    server_id: Some("srv-1".into()),
                    tool: Some("read".into()),
                    decision: RuleDecision::Allow,
                    attention: Some(Attention::Badge),
                    scope: RuleScope::Always,
                    expires_at: None,
                    condition: None,
                    condition_error: None,
                    created_at: created,
                },
                Rule {
                    id: "rule-session".into(),
                    agent_id: Some("agt-1".into()),
                    server_id: None,
                    tool: None,
                    decision: RuleDecision::Deny,
                    attention: None,
                    scope: RuleScope::Session,
                    expires_at: None,
                    condition: None,
                    condition_error: None,
                    created_at: created,
                },
                Rule {
                    id: "rule-expired".into(),
                    agent_id: None,
                    server_id: Some("srv-1".into()),
                    tool: Some("write_*".into()),
                    decision: RuleDecision::Ask,
                    attention: Some(Attention::Open),
                    scope: RuleScope::Always,
                    expires_at: Some(created - chrono::Duration::minutes(1)),
                    condition: None,
                    condition_error: None,
                    created_at: created,
                },
            ],
            on_timeout: TimeoutBehavior::AllowReadOnly,
            do_not_disturb: true,
            rate_limit_per_minute: Some(60),
            hold_timeout_secs: 45,
            clients: Vec::new(),
            tokens: Vec::new(),
        };

        original.save(&path).expect("save");
        let loaded = PrismConfig::load(&path).expect("load");

        assert_eq!(loaded.listen_port, 9099);
        assert_eq!(loaded.listen_address, ListenAddress::Network);
        assert!(!loaded.auto_open_on_pending);
        assert_eq!(loaded.panel_anchor, PanelAnchor::BottomLeft);
        assert_eq!(loaded.servers, original.servers);
        assert!(!loaded.servers[0].exposes("delete_file"));
        assert!(loaded.servers[0].exposes("read_file"));
        assert_eq!(loaded.agents, original.agents);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].id, "rule-always");
        assert_eq!(loaded.rules[0].scope, RuleScope::Always);
        assert_eq!(loaded.rules[0].attention, Some(Attention::Badge));
        assert_eq!(loaded.on_timeout, TimeoutBehavior::AllowReadOnly);
        assert!(loaded.do_not_disturb);
        assert_eq!(loaded.rate_limit_per_minute, Some(60));
        assert_eq!(loaded.hold_timeout_secs, 45);
    }

    #[test]
    fn legacy_config_gets_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("prism.json");
        std::fs::write(
            &path,
            r#"{"agents":[{"id":"a","name":"old","created_at":"2026-01-01T00:00:00Z"}],
                "rules":[{"id":"r","agent_id":"a","server_id":null,"tool":null,"decision":"allow",
                "scope":"always","created_at":"2026-01-01T00:00:00Z"}]}"#,
        )
        .expect("write");
        let loaded = PrismConfig::load(&path).expect("load");
        assert_eq!(loaded.agents[0].posture, Posture::FirstUse);
        assert_eq!(loaded.agents[0].attention, Attention::Silent);
        assert_eq!(loaded.rules[0].attention, None);
        assert_eq!(loaded.rules[0].expires_at, None);
        assert_eq!(loaded.on_timeout, TimeoutBehavior::Deny);
        assert_eq!(loaded.hold_timeout_secs, 120);
    }

    #[test]
    fn default_listen_port_is_9086() {
        assert_eq!(PrismConfig::default().listen_port, 9086);
        assert_eq!(
            PrismConfig::default().listen_address,
            ListenAddress::Loopback
        );
        let bare: PrismConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(bare.listen_address, ListenAddress::Loopback);
    }
}

#[cfg(test)]
mod agent_tests {
    use super::*;

    fn agent(id: &str, name: &str, client_id: Option<&str>, host: Option<&str>) -> AgentConfig {
        AgentConfig {
            id: id.into(),
            name: name.into(),
            client_name: name.into(),
            client_version: None,
            status: AgentStatus::Approved,
            created_at: Utc::now(),
            decided_at: Some(Utc::now()),
            posture: Posture::Guided,
            attention: Attention::Badge,
            client_id: client_id.map(str::to_string),
            host: host.map(str::to_string),
        }
    }

    fn client(id: &str, name: &str) -> OAuthClient {
        OAuthClient {
            client_id: id.into(),
            client_name: name.into(),
            redirect_uris: vec![],
            created_at: Utc::now(),
            agent_id: None,
            origin: None,
        }
    }

    #[test]
    fn per_client_harness_agents_fold_into_the_harness_record_on_load() {
        let mut config = PrismConfig::default();
        // Written by a version before the host field existed: only the id says what it is.
        let mut hooked = agent("host:codex", "Codex", None, None);
        hooked.posture = Posture::Trusted;
        hooked.attention = Attention::Silent;
        config.agents.push(hooked);
        config
            .agents
            .push(agent("old-codex", "Codex", Some("c1"), None));
        config
            .agents
            .push(agent("old-claude", "Claude Code (2)", Some("c2"), None));
        config.agents.push(agent("toad", "Toad", Some("c3"), None));
        config.clients.push(client("c1", "Codex"));
        config.clients.push(client("c2", "Claude Code"));
        config.clients.push(client("c3", "Toad"));
        config.tokens.push(TokenRecord {
            hash: "h".into(),
            kind: TokenKind::Refresh,
            agent_id: "old-codex".into(),
            client_id: Some("c1".into()),
            created_at: Utc::now(),
            expires_at: None,
        });
        config.rules.push(Rule {
            id: "r".into(),
            agent_id: Some("old-claude".into()),
            server_id: Some("s".into()),
            tool: None,
            decision: RuleDecision::Allow,
            attention: None,
            scope: RuleScope::Always,
            expires_at: None,
            condition: None,
            condition_error: None,
            created_at: Utc::now(),
        });

        assert!(config.merge_harness_agents());

        let ids: Vec<&str> = config.agents.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["host:codex", "toad", "host:claude-code"]);
        let codex = config.agents.iter().find(|a| a.id == "host:codex").unwrap();
        assert_eq!(codex.host.as_deref(), Some("codex"), "derived from the id");
        assert_eq!(
            codex.posture,
            Posture::Guided,
            "the MCP agent's posture governed calls"
        );
        assert_eq!(codex.attention, Attention::Badge);
        let claude = config
            .agents
            .iter()
            .find(|a| a.id == "host:claude-code")
            .unwrap();
        assert_eq!(claude.name, "Claude Code");
        assert_eq!(claude.host.as_deref(), Some("claude-code"));
        assert_eq!(claude.posture, Posture::Guided);
        assert_eq!(config.tokens[0].agent_id, "host:codex");
        assert_eq!(
            config.rules[0].agent_id.as_deref(),
            Some("host:claude-code")
        );
        assert_eq!(config.client_agent_id("c1").as_deref(), Some("host:codex"));
        assert_eq!(
            config.client_agent_id("c2").as_deref(),
            Some("host:claude-code")
        );
        assert_eq!(config.client_agent_id("c3").as_deref(), Some("toad"));
        assert_eq!(config.agent_client_ids("host:codex"), ["c1"]);
        assert!(
            !config.merge_harness_agents(),
            "a second pass moves nothing"
        );
    }

    #[test]
    fn a_new_harness_client_joins_the_existing_record_and_asks_once_for_posture() {
        let mut config = PrismConfig::default();
        let mut hooked = agent("host:claude-code", "Claude Code", None, Some("claude-code"));
        hooked.posture = Posture::Trusted;
        config.agents.push(hooked);
        config.clients.push(client("c1", "Claude Code"));
        config.clients.push(client("c2", "claude-code"));
        config.clients.push(client("c9", "Unrelated MCP Client"));

        let (first, created) = config.find_or_request_agent_for_client(&config.clients[0].clone());
        assert!(!created);
        assert_eq!(first.id, "host:claude-code");
        assert_eq!(
            first.posture,
            Posture::FirstUse,
            "hook default gives way to the MCP default"
        );
        let (second, created) = config.find_or_request_agent_for_client(&config.clients[1].clone());
        assert!(!created);
        assert_eq!(second.id, first.id);
        assert_eq!(config.agent_client_ids("host:claude-code"), ["c1", "c2"]);

        let (other, created) = config.find_or_request_agent_for_client(&config.clients[2].clone());
        assert!(created);
        assert_eq!(other.name, "Unrelated MCP Client");
        assert!(other.host.is_none());
        assert_eq!(other.status, AgentStatus::Pending);

        let fresh = client("c3", "Codex CLI");
        config.clients.push(fresh.clone());
        let (codex, created) = config.find_or_request_agent_for_client(&fresh);
        assert!(created);
        assert_eq!(codex.id, "host:codex");
        assert_eq!(codex.status, AgentStatus::Pending);
    }

    #[test]
    fn legacy_agent_without_status_loads_as_approved() {
        let json = r#"{"agents":[{"id":"a1","name":"Old","token":"tok","created_at":"2026-09-01T00:00:00Z"}]}"#;
        let config: PrismConfig = serde_json::from_str(json).expect("legacy config parses");
        assert_eq!(config.agents[0].status, AgentStatus::Approved);
    }
}
