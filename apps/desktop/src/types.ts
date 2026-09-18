export type BackendStatus =
  | { kind: "starting" }
  | { kind: "running"; tool_count: number }
  | { kind: "failed"; error: string }
  | { kind: "stopped" }
  | { kind: "sign_in_required" };

/** How a remote server is authenticated. Secrets live in the keyring, never in prism.json. */
export type HttpAuth = "none" | "header" | "oauth";

/** Why agents cannot connect, when they cannot. `holder` names the other program when Prism can tell. */
export type ListenerState =
  | { kind: "listening" }
  | { kind: "port_in_use"; port: number; holder: "prism" | null }
  | { kind: "failed"; port: number; error: string }
  | { kind: "stopped" };

/** Loopback is this machine only; network is every interface. */
export type ListenAddress = "loopback" | "network";

export interface GatewayStatus {
  /** The port agents dial: the bound one while listening, otherwise the configured one. */
  listen_port: number;
  listening: boolean;
  listener: ListenerState;
  listen_address: ListenAddress;
  /** The MCP URL for agents on other machines, while on the network and there is a route out. */
  network_url: string | null;
  servers_running: number;
  servers_total: number;
  agent_count: number;
  pending_count: number;
  pending_agents: number;
  /** Approved agents whose client is signing in again and waiting for a yes. */
  pending_signins: number;
  auto_open_on_pending: boolean;
  do_not_disturb: boolean;
}

/** What an agent's calls do when no rule covers them. */
export type Posture = "supervised" | "first_use" | "guided" | "trusted";

/** How loudly Prism surfaces a call it resolved without asking. */
export type Attention = "silent" | "badge" | "notify" | "open";

export type TimeoutBehavior = "deny" | "allow_read_only";

export interface Settings {
  on_timeout: TimeoutBehavior;
  do_not_disturb: boolean;
  rate_limit_per_minute: number | null;
  hold_timeout_secs: number;
  auto_open_on_pending: boolean;
  /** Which corner the panel opens in; auto follows the desktop's bar. */
  panel_anchor: PanelAnchor;
  /** The global shortcut as configured: null is the built-in one, empty turns it off. Applied at the next launch. */
  panel_shortcut: string | null;
}

export type PanelAnchor = "auto" | "top-right" | "top-left" | "bottom-right" | "bottom-left";

/** A token an agent holds. Prism keeps only the hash, so this is all there is to show. */
export interface TokenView {
  kind: "access" | "refresh" | "manual";
  created_at: string;
  expires_at: string | null;
}

/** Present only in the create/replace response, never in agent listings. */
export interface ManualToken {
  agent_id: string;
  token: string;
}

export interface ToolInfo {
  name: string;
  description: string | null;
  read_only: boolean;
  destructive: boolean;
  /** False when the panel hid it: agents neither list nor call it. */
  exposed: boolean;
}

export type HookDirection = "send" | "recv" | "both";

export interface ServerHookConfig {
  command: string;
  args?: string[];
  direction?: HookDirection;
  timeout_secs?: number;
}

export interface ServerView {
  id: string;
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  credentials_stored: boolean;
  enabled: boolean;
  status: BackendStatus;
  /** Endpoint of a remote server; null for a stdio one. */
  url: string | null;
  auth: HttpAuth;
  /** Tools the panel hid from every agent, by name. */
  hidden_tools: string[];
  /** Subprocess hook to intercept and patch MCP messages. */
  hook?: ServerHookConfig | null;
}

export type AgentStatus = "pending" | "approved" | "denied";

export interface AgentConfig {
  id: string;
  name: string;
  client_name: string;
  client_version: string | null;
  status: AgentStatus;
  created_at: string;
  decided_at: string | null;
  posture: Posture;
  attention: Attention;
  /** The OAuth client this agent signs in as; absent for manually configured agents. */
  client_id?: string | null;
  /** Set for an agent host observed through its hooks, e.g. "claude-code". Never holds a token. */
  host?: string | null;
  /** True while at least one MCP session for this agent is open. */
  connected: boolean;
  /** Live tokens, newest last. Empty for agents that never signed in. */
  tokens: TokenView[];
  /** The OAuth clients that sign in as this agent: one per scope or install a harness registered from. */
  clients: ClientView[];
}

/** One registered OAuth client under its agent. */
export interface ClientView {
  client_id: string;
  client_name: string;
  created_at: string;
  /** Where it registered from; null is this machine. */
  origin: string | null;
  signed_in: boolean;
}

/** An OAuth sign-in parked until you answer. Only shown for agents that were already approved. */
export interface PendingSignIn {
  id: string;
  agent_id: string;
  agent_name: string;
  client_name: string;
  client_id: string;
  requested_at: string;
  needs_consent: boolean;
  /** This client never held a token: the harness is connecting from a new scope or install. */
  new_client: boolean;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface Offer {
  kind: "path_under" | "host";
  value: string;
  label: string;
}

export interface PendingCall {
  id: string;
  agent_id: string;
  agent_name: string;
  server_id: string;
  server_name: string;
  tool: string;
  arguments: unknown;
  facets?: string[];
  offers?: Offer[];
  requested_at: string;
  /** When the hold times out. */
  deadline: string | null;
  posture: Posture;
  reason: "policy" | "rate_limit";
}

export type DecisionScope = "once" | "session" | "always" | { for: { minutes: number } };

export interface Decision {
  verdict: "allow" | "deny";
  scope: DecisionScope;
  /** How wide the remembered rule reaches. Defaults to this tool. */
  target?: "tool" | "server" | "agent";
  condition?: JsonValue;
}

export type RuleDecision = "allow" | "deny" | "ask";

export interface Rule {
  id: string;
  agent_id: string | null;
  server_id: string | null;
  /** Exact name or a glob with `*`. */
  tool: string | null;
  decision: RuleDecision;
  /** null inherits the agent's attention. */
  attention: Attention | null;
  scope: "session" | "always";
  expires_at: string | null;
  created_at: string;
  condition?: JsonValue;
  condition_error?: string | null;
}

export interface NewRule {
  agent_id: string | null;
  server_id: string | null;
  tool: string | null;
  decision: RuleDecision;
  attention?: Attention | null;
  scope?: "session" | "always";
  minutes?: number | null;
}

export interface AuditEntry {
  id: string;
  at: string;
  agent_id: string;
  agent_name: string;
  server_id: string;
  tool: string;
  verdict: "allowed" | "denied" | "timeout" | "error";
  source:
    | { kind: "rule"; rule_id: string }
    | { kind: "human" }
    | { kind: "tripwire" }
    | { kind: "timeout" }
    | { kind: "unapproved" }
    | { kind: "posture"; posture: Posture }
    | { kind: "do_not_disturb" }
    | { kind: "cancelled" }
    | { kind: "observed" };
  duration_ms: number;
  error: string | null;
  attention: Attention;
  /** Present for a native action seen through a host hook. */
  native?: NativeDetail | null;
  facets?: string[];
}

/** What the record keeps about a native action. `subject` is one redacted line, never the raw input. */
export interface NativeDetail {
  host: string;
  session?: string | null;
  cwd?: string | null;
  subject: string;
  /** Shadow deny-list rule id this action would have tripped. Nothing was held. */
  would_hold?: string | null;
  agent_type?: string | null;
  /** An MCP tool Prism serves, seen again through the hook; the gateway already logged the call. */
  via_prism: boolean;
}

export interface ShadowRule {
  id: string;
  summary: string;
}

export interface HostStatus {
  host: string;
  hook_url: string;
  last_event_at: string | null;
  actions_7d: number;
  by_reason: { reason: string; count: number }[];
}

/** Desktop only: where a host's user-level hooks file lives and whether the current hook URL is in it. */
export interface HostSetup {
  host: string;
  settings_path: string;
  mcp_path: string;
  mcp_configured: boolean;
  hook_installed: boolean;
  hooks_disabled: boolean;
  setup_present: boolean;
  events_received: boolean;
  problem: string | null;
}

export interface HarnessChanges {
  paths: string[];
  backups: string[];
}

export interface NativeStatus {
  window: AuditWindow;
  observe_native: boolean;
  last_event_at: string | null;
  actions_7d: number;
  would_hold_7d: number;
  by_reason: { reason: string; count: number }[];
  rules: ShadowRule[];
  hosts: HostStatus[];
  setup: HostSetup[];
}

export interface HookInstallResult {
  path: string;
  backup: string | null;
}

export interface ConnectSnippet {
  url: string;
  mcp_json: string;
  /** For agents on other machines; null while the listener is loopback only. */
  network_url: string | null;
}

export type GatewayEvent =
  | { type: "pending_call"; data: PendingCall }
  | { type: "call_decided"; data: { id: string; decision: Decision } }
  | { type: "call_cancelled"; data: { id: string } }
  | { type: "agent_requested"; data: AgentConfig }
  | { type: "sign_in_requested"; data: PendingSignIn }
  | { type: "sign_in_decided"; data: { id: string; approved: boolean } }
  | { type: "agent_decided"; data: { agent_id: string; status: AgentStatus } }
  | { type: "agent_connected"; data: { agent_id: string } }
  | { type: "agent_disconnected"; data: { agent_id: string } }
  | { type: "agent_updated"; data: { agent_id: string } }
  | { type: "settings_changed" }
  | { type: "listener_changed" }
  | { type: "server_status"; data: { server_id: string; status: BackendStatus } }
  | { type: "tools_changed"; data: { server_id: string } }
  | { type: "audit"; data: AuditEntry }
  | { type: "rules_changed" };

/** A newer release than the running one. `installable` is false for package-manager installs on Linux. */
export interface UpdateInfo {
  version: string;
  current: string;
  notes: string | null;
  date: string | null;
  installable: boolean;
}

export interface UpdateStatus {
  current: string;
  available: UpdateInfo | null;
  checked_at: string | null;
  installable: boolean;
}

export type UpdateEvent =
  | { state: "available"; version: string; current: string; notes: string | null; date: string | null; installable: boolean }
  | { state: "up_to_date" }
  | { state: "downloading"; downloaded: number; total: number | null }
  | { state: "installing" }
  | { state: "error"; message: string };

/** The last few days summed up. `attention` counts held calls, denials and would-ask native actions. */
export interface ActivitySummary {
  window: AuditWindow;
  days: number;
  total: number;
  attention: number;
  mcp: { allowed: number; denied: number; asked: number; errors: number };
  /** Busiest first. */
  agents: AgentActivity[];
  /** Oldest first, today last. */
  daily: DayActivity[];
}

export interface AgentActivity {
  id: string;
  name: string;
  host: boolean;
  total: number;
  attention: number;
}

export interface DayActivity {
  /** Local calendar day, YYYY-MM-DD. */
  date: string;
  routine: number;
  attention: number;
}

export interface AuditWindow {
  days: number;
  first_day: string;
  last_day: string;
  snapshot_at: string;
  oldest_available_at: string | null;
  newest_available_at: string | null;
  retention_days: number;
  archive_count: number;
  max_file_bytes: number;
  max_history_bytes: number;
  retained_bytes: number;
  size_limited: boolean;
  full_window_guaranteed: boolean;
}
export interface AuditPage {
  entries: AuditEntry[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  window: AuditWindow;
}
export interface ExportReport { path: string; metadata_path: string; total: number; }
