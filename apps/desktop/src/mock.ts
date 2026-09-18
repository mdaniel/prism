import { HOSTS } from "./hosts";
/** Fixture backend for `pnpm dev` in a plain browser, where Tauri's invoke is absent. Never used inside the app. */
import type {
  HttpAuth,
  ActivitySummary,
  AgentActivity,
  DayActivity,
  AgentConfig,
  AuditEntry,
  AuditWindow,
  ConnectSnippet,
  Decision,
  GatewayStatus,
  ListenAddress,
  ListenerState,
  NewRule,
  PendingCall,
  PendingSignIn,
  Rule,
  ServerHookConfig,
  ServerView,
  Settings,
  ToolInfo,
} from "./types";

const iso = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString();

const servers: ServerView[] = [
  { id: "s1", name: "filesystem", command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/george/Projects"], env: {}, credentials_stored: true, enabled: true, status: { kind: "running", tool_count: 11 }, url: null, auth: "none", hidden_tools: [] },
  { id: "s2", name: "github", command: "docker", args: ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"], env: {}, credentials_stored: true, enabled: true, status: { kind: "running", tool_count: 42 }, url: null, auth: "none", hidden_tools: [] },
  { id: "s3", name: "postgres", command: "uvx", args: ["mcp-server-postgres", "postgres://localhost/app"], env: {}, credentials_stored: true, enabled: true, status: { kind: "failed", error: "connection refused (127.0.0.1:5432)" }, url: null, auth: "none", hidden_tools: [] },
  { id: "s4", name: "linear", command: "", args: [], env: {}, credentials_stored: false, enabled: true, status: { kind: "sign_in_required" }, url: "https://mcp.linear.app/mcp", auth: "oauth", hidden_tools: [] },
  { id: "s5", name: "cloudflare docs", command: "", args: [], env: {}, credentials_stored: false, enabled: true, status: { kind: "running", tool_count: 2 }, url: "https://docs.mcp.cloudflare.com/mcp", auth: "none", hidden_tools: [] },
];
const agents: AgentConfig[] = [
  { id: "host:claude-code", name: "Claude Code", client_name: "claude-code", client_version: "2.1.14", status: "approved", created_at: iso(3600 * 30), decided_at: iso(3600 * 30), posture: "guided", attention: "badge", client_id: null, host: "claude-code", connected: true, tokens: [{ kind: "access", created_at: iso(1200), expires_at: iso(-2400) }, { kind: "refresh", created_at: iso(3600 * 26), expires_at: iso(-3600 * 24 * 29) }, { kind: "refresh", created_at: iso(3600 * 3), expires_at: iso(-3600 * 24 * 30) }], clients: [{ client_id: "c-claude-user", client_name: "Claude Code", created_at: iso(3600 * 26), origin: null, signed_in: true }, { client_id: "c-claude-prism", client_name: "Claude Code", created_at: iso(3600 * 3), origin: null, signed_in: true }, { client_id: "c-claude-recoil", client_name: "claude-code", created_at: iso(900), origin: null, signed_in: false }] },
  { id: "host:codex", name: "Codex", client_name: "codex", client_version: "0.42.0", status: "approved", created_at: iso(3600 * 20), decided_at: iso(3600 * 20), posture: "first_use", attention: "silent", client_id: null, host: "codex", connected: false, tokens: [{ kind: "refresh", created_at: iso(3600 * 20), expires_at: iso(-3600 * 24 * 30) }], clients: [{ client_id: "c-codex", client_name: "Codex", created_at: iso(3600 * 20), origin: null, signed_in: true }] },
  { id: "host:cursor", host: "cursor", name: "Cursor", client_name: "cursor", client_version: "1.7.0", status: "approved", created_at: iso(600), decided_at: iso(590), posture: "first_use", attention: "silent", client_id: "c-cursor", connected: false, tokens: [{ kind: "refresh", created_at: iso(600), expires_at: iso(-3600 * 24 * 30) }], clients: [{ client_id: "c-cursor", client_name: "cursor", created_at: iso(600), origin: null, signed_in: true }] },
  { id: "a3", name: "Toad MCP Gateway", client_name: "Toad MCP Gateway", client_version: "0.1.0", status: "pending", created_at: iso(12), decided_at: null, posture: "first_use", attention: "silent", client_id: "c-toad", connected: false, tokens: [], clients: [{ client_id: "c-toad", client_name: "Toad MCP Gateway", created_at: iso(12), origin: null, signed_in: false }] },
  { id: "a4", name: "some-random-script", client_name: "some-random-script", client_version: null, status: "denied", created_at: iso(3600 * 50), decided_at: iso(3600 * 50), posture: "supervised", attention: "silent", client_id: null, connected: false, tokens: [], clients: [] },
];
let pending: PendingCall[] = [
  { id: "p1", agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "s1", server_name: "filesystem", tool: "write_file", arguments: { path: "/home/george/Projects/prism/README.md", content: "# Prism\n\nA local MCP gateway…" }, requested_at: iso(23), deadline: iso(-97), posture: "guided", reason: "policy", facets: ["path: ~/Projects/prism/README.md (write)"], offers: [{ kind: "path_under", value: "/home/george/Projects/prism", label: "Under ~/Projects/prism" }] },
];
let rules: Rule[] = [
  { id: "r1", agent_id: "host:claude-code", server_id: "s1", tool: "read_file", decision: "allow", attention: null, scope: "always", expires_at: null, created_at: iso(3600 * 5) },
  { id: "r9", agent_id: "host:claude-code", server_id: "s1", tool: "write_file", decision: "allow", attention: null, scope: "always", expires_at: null, created_at: iso(60 * 40), condition: { path: { under: "/home/george/Projects/prism" } } },
  { id: "r2", agent_id: "host:cursor", server_id: "s2", tool: "create_issue", decision: "allow", attention: null, scope: "session", expires_at: null, created_at: iso(300) },
  { id: "r3", agent_id: null, server_id: "s3", tool: null, decision: "deny", attention: "notify", scope: "always", expires_at: null, created_at: iso(3600 * 30) },
  { id: "r4", agent_id: "host:claude-code", server_id: "s2", tool: null, decision: "allow", attention: null, scope: "always", expires_at: iso(-60 * 24), created_at: iso(360) },
  { id: "r5", agent_id: "host:claude-code", server_id: "s1", tool: "delete_*", decision: "ask", attention: null, scope: "always", expires_at: null, created_at: iso(3600 * 2) },
  { id: "r6", agent_id: "host:codex", server_id: "s5", tool: null, decision: "allow", attention: null, scope: "always", expires_at: null, created_at: iso(3600 * 8) },
  { id: "r7", agent_id: "host:cursor", server_id: "s1", tool: "write_file", decision: "ask", attention: "notify", scope: "always", expires_at: null, created_at: iso(3600 * 12) },
  { id: "r8", agent_id: null, server_id: "s4", tool: null, decision: "deny", attention: null, scope: "session", expires_at: null, created_at: iso(120) },
];
const HOOK_TOKEN = "k3Jx9v2mQd8sT1uWbC4eF6gH7iJ0lM_nO-pQrStUvWx";
const nativeStatus = {
  window: mockWindow(),
  observe_native: true,
  hosts: [
    { host: "claude-code", hook_url: `http://127.0.0.1:9086/hooks/claude-code/${HOOK_TOKEN}`, last_event_at: iso(30), actions_7d: 390, by_reason: [{reason: "git_force", count: 1}, {reason: "write_outside_cwd", count: 2}] },
    { host: "codex", hook_url: `http://127.0.0.1:9086/hooks/codex/${HOOK_TOKEN}`, last_event_at: iso(1800), actions_7d: 22, by_reason: [] },
  ],
  setup: [
    { host: "claude-code", settings_path: "/home/george/.claude/settings.json", mcp_path: "/home/george/.claude.json", mcp_configured: true, hook_installed: true, hooks_disabled: false, setup_present: true, events_received: true, problem: null as string | null },
    { host: "codex", settings_path: "/home/george/.codex/hooks.json", mcp_path: "/home/george/.codex/config.toml", mcp_configured: true, hook_installed: true, hooks_disabled: false, setup_present: true, events_received: false, problem: null as string | null },
  ],
  last_event_at: iso(30),
  actions_7d: 412,
  would_hold_7d: 3,
  by_reason: [
    { reason: "write_outside_cwd", count: 2 },
    { reason: "git_force", count: 1 },
  ],
  rules: [
    { id: "rm_outside_cwd", summary: "Recursive delete of a path outside the working directory" },
    { id: "git_force", summary: "git push --force, reset --hard, or clean -f" },
    { id: "pipe_to_shell", summary: "curl or wget piped into a shell or interpreter" },
    { id: "sudo", summary: "A command run through sudo or doas" },
    { id: "secret_read", summary: "Reading SSH keys, cloud credentials, or a .env file" },
    { id: "sensitive_write", summary: "Writing under ~/.ssh, ~/.aws, ~/.config/gh, or a shell rc file" },
    { id: "write_outside_cwd", summary: "Writing a file outside the working directory" },
  ],
};
for (const h of HOSTS.slice(2)) {
  const files: Record<string, [string, string]> = {
    cursor: [".cursor/mcp.json", ".cursor/hooks.json"],
    opencode: [".config/opencode/opencode.json", ".config/opencode/plugins/prism.js"],
    goose: [".config/goose/config.yaml", ".agents/plugins/prism-goose/hooks/hooks.json"],
    antigravity: [".gemini/config/mcp_config.json", ".gemini/config/hooks.json"],
  };
  const [mcp, hooks] = files[h.host];
  nativeStatus.hosts.push({ host: h.host, hook_url: `http://127.0.0.1:9086/hooks/${h.host}/${HOOK_TOKEN}`, last_event_at: "", actions_7d: 0, by_reason: [] });
  nativeStatus.setup.push({ host: h.host, mcp_path: `/home/george/${mcp}`, settings_path: `/home/george/${hooks}`, mcp_configured: false, hook_installed: false, setup_present: false, hooks_disabled: false, events_received: false, problem: null });
}
const nat = (host: string, subject: string, extra: Partial<import("./types").NativeDetail> = {}) => ({ host, subject, cwd: "/home/george/Projects/prism", session: "s-1", via_prism: false, ...extra });
/** Mirrors prism_core::activity::needs_attention. */
const needsAttention = (e: AuditEntry) => (e.native ? !!e.native.would_hold : e.source.kind === "tripwire" || e.source.kind === "human" || e.source.kind === "timeout" || e.verdict === "denied");
function localDay(at: string) {
  const d = new Date(at);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
function mockWindow(days = 7, at = iso(0), entries: AuditEntry[] = []): AuditWindow {
  const first = new Date(at); first.setDate(first.getDate() - days + 1);
  const sorted = entries.map(e => e.at).sort();
  return {days, first_day:localDay(first.toISOString()), last_day:localDay(at), snapshot_at:at,
    oldest_available_at:sorted[0] ?? null, newest_available_at:sorted.at(-1) ?? null,
    retention_days:30, archive_count:3, max_file_bytes:5242880, max_history_bytes:20971520,
    retained_bytes:0, size_limited:true, full_window_guaranteed:false};
}
function mockQuery(filter: import("./state").ActivityFilter = {}) {
  const window = mockWindow(filter.days ?? 7, filter.at ?? iso(0), audit);
  const entries = audit.filter(e => !e.native?.via_prism && e.at <= window.snapshot_at && localDay(e.at) >= window.first_day && localDay(e.at) <= window.last_day)
    .filter(e => !filter.agentId || e.agent_id === filter.agentId)
    .filter(e => filter.attention === undefined || needsAttention(e) === filter.attention)
    .filter(e => !filter.day || localDay(e.at) === filter.day)
    .filter(e => !filter.reason || e.native?.would_hold === filter.reason)
    .filter(e => !filter.nativeOnly || !!e.native)
    .sort((a,b) => b.at.localeCompare(a.at) || b.id.localeCompare(a.id));
  return {entries, window};
}
/** All chart counts come from materialized fixture rows, just like their drilldowns. */
function activitySummary(): ActivitySummary {
  const {entries:seen, window} = mockQuery();
  const byAgent = new Map<string, AgentActivity>();
  const daily: DayActivity[] = Array.from({length:7}, (_,i) => {
    const d = new Date(window.last_day + "T12:00:00"); d.setDate(d.getDate() - 6 + i);
    return {date:localDay(d.toISOString()), routine:0, attention:0};
  });
  for (const e of seen) {
    const a = byAgent.get(e.agent_id) ?? {id:e.agent_id, name:e.agent_name, host:e.agent_id.startsWith("host:"), total:0, attention:0};
    a.total++; if (needsAttention(e)) a.attention++; byAgent.set(e.agent_id,a);
    const day = daily.find(d => d.date === localDay(e.at))!;
    if (needsAttention(e)) day.attention++; else day.routine++;
  }
  const mcp = seen.filter(e => !e.native);
  return {window, days:7, total:seen.length, attention:seen.filter(needsAttention).length,
    mcp:{allowed:mcp.filter(e=>e.verdict==="allowed").length, denied:mcp.filter(e=>e.verdict==="denied").length,
      asked:mcp.filter(e=>["human","timeout","tripwire"].includes(e.source.kind)).length, errors:mcp.filter(e=>e.verdict==="error").length},
    agents:[...byAgent.values()].sort((a,b)=>b.total-a.total), daily};
}

let audit: AuditEntry[] = [
  { id: "n1", at: iso(30), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "claude-code", tool: "Bash", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("claude-code", "cargo test -p prism-core") },
  { id: "n2", at: iso(55), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "claude-code", tool: "Edit", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("claude-code", "~/Projects/prism/crates/prism-core/src/native.rs") },
  { id: "n3", at: iso(140), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "claude-code", tool: "Bash", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("claude-code", "git push --force origin main", { would_hold: "git_force" }) },
  { id: "n6", at: iso(1800), agent_id: "host:codex", agent_name: "Codex", server_id: "codex", tool: "apply_patch", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("codex", "src/lib.rs, README.md") },
  { id: "n4", at: iso(300), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "claude-code", tool: "WebFetch", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("claude-code", "https://code.claude.com") },
  { id: "n5", at: iso(320), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "claude-code", tool: "mcp__prism__filesystem__read_file", verdict: "allowed", source: { kind: "observed" }, duration_ms: 0, error: null, attention: "silent", native: nat("claude-code", "mcp__prism__filesystem__read_file", { via_prism: true }) },
  { id: "e1", at: iso(40), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "s1", tool: "read_file", verdict: "allowed", source: { kind: "rule", rule_id: "r1" }, duration_ms: 12, error: null, attention: "silent" },
  { id: "e2", at: iso(95), agent_id: "host:cursor", agent_name: "Cursor", server_id: "s2", tool: "create_issue", verdict: "allowed", source: { kind: "human" }, duration_ms: 840, error: null, attention: "silent" },
  { id: "e3", at: iso(200), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "s3", tool: "query", verdict: "denied", source: { kind: "rule", rule_id: "r3" }, duration_ms: 1, error: null, attention: "notify" },
  { id: "e4", at: iso(500), agent_id: "host:cursor", agent_name: "Cursor", server_id: "s1", tool: "delete_file", verdict: "timeout", source: { kind: "timeout" }, duration_ms: 120000, error: null, attention: "badge" },
  { id: "e0", at: iso(10), agent_id: "a3", agent_name: "codex-cli", server_id: "", tool: "filesystem__read_file", verdict: "denied", source: { kind: "unapproved" }, duration_ms: 0, error: "Prism has not approved 'codex-cli' yet. Open the Prism panel and approve it, then retry.", attention: "silent" },
  { id: "e6", at: iso(70), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "s1", tool: "list_directory", verdict: "allowed", source: { kind: "posture", posture: "guided" }, duration_ms: 8, error: null, attention: "badge" },
  { id: "e5", at: iso(900), agent_id: "host:claude-code", agent_name: "Claude Code", server_id: "s2", tool: "search_code", verdict: "error", source: { kind: "human" }, duration_ms: 3300, error: "backend exited with status 1", attention: "silent" },
];
// Earlier days are actual rows so every chart segment has a matching log.
for (let day = 1; day <= 6; day++) {
  for (let i = 0; i < 18 + day * 7; i++) {
    const date = new Date(); date.setDate(date.getDate() - day); date.setHours(12, 0, i, 0);
    const host = i % 3 === 0 ? "codex" : "claude-code";
    audit.push({...audit[0], id:`earlier-${day}-${i}`, at:date.toISOString(), agent_id:`host:${host}`,
      agent_name:host === "codex" ? "Codex" : "Claude Code", server_id:host,
      native:nat(host, i === 0 ? "git reset --hard" : "cargo check", i === 0 ? {would_hold:"git_force"} : {})});
  }
}
let signins: PendingSignIn[] = [
  { id: "si1", agent_id: "host:claude-code", agent_name: "Claude Code", client_name: "claude-code", client_id: "c-claude-recoil", requested_at: iso(8), needs_consent: true, new_client: true },
];
let settings: Settings = { on_timeout: "deny", do_not_disturb: false, rate_limit_per_minute: null, hold_timeout_secs: 120, auto_open_on_pending: true, panel_anchor: "auto", panel_shortcut: null };
const tools: Record<string, ToolInfo[]> = {
  s1: [
    { name: "read_file", description: "Read the complete contents of a file.", read_only: true, destructive: false, exposed: true },
    { name: "read_multiple_files", description: "Read several files at once.", read_only: true, destructive: false, exposed: true },
    { name: "write_file", description: "Create or overwrite a file.", read_only: false, destructive: true, exposed: true },
    { name: "edit_file", description: "Make line-based edits to a text file.", read_only: false, destructive: false, exposed: true },
    { name: "list_directory", description: "List files and directories.", read_only: true, destructive: false, exposed: true },
    { name: "delete_file", description: "Delete a file.", read_only: false, destructive: true, exposed: true },
  ],
  s2: [
    { name: "create_issue", description: "Open a GitHub issue.", read_only: false, destructive: false, exposed: true },
    { name: "search_code", description: "Search code across repositories.", read_only: true, destructive: false, exposed: true },
    { name: "create_pull_request", description: "Open a pull request.", read_only: false, destructive: false, exposed: true },
  ],
  s3: [],
};

const delay = <T,>(v: T) => new Promise<T>((r) => setTimeout(() => r(v), 60));

/** `?port=busy` in the browser shows the clash notice; `?port=prism` names the other copy. */
const portScenario = new URLSearchParams(location.search).get("port");
let listenPort = 9086;
let listenAddress: ListenAddress = "loopback";
const networkUrl = () => (listenAddress === "network" && listener.kind === "listening" ? `http://192.168.1.20:${listenPort}/mcp` : null);
let listener: ListenerState = portScenario ? { kind: "port_in_use", port: 9086, holder: portScenario === "prism" ? "prism" : null } : { kind: "listening" };

export const mock = {
  get_status: (): Promise<GatewayStatus> =>
    delay({ listen_port: listenPort, listening: listener.kind === "listening", listener, listen_address: listenAddress, network_url: networkUrl(), servers_running: servers.filter((s) => s.status.kind === "running").length, servers_total: servers.length, agent_count: agents.length, pending_count: pending.length, pending_agents: agents.filter((a) => a.status === "pending").length, pending_signins: signins.length, auto_open_on_pending: settings.auto_open_on_pending, do_not_disturb: settings.do_not_disturb }),
  list_servers: () => delay(servers),
  add_server: (a: { args: { name: string; command?: string; args?: string[]; env?: Record<string, string>; url?: string; auth?: HttpAuth; headers?: Record<string, string> } }) => {
    const remote = !!a.args.url;
    const auth = a.args.auth ?? "none";
    const s: ServerView = {
      id: `s${Date.now()}`,
      hidden_tools: [],
      name: a.args.name,
      command: remote ? "" : (a.args.command ?? ""),
      args: [],
      env: {},
      credentials_stored: (a.args.args?.length ?? 0) > 0 || Object.keys(a.args.env ?? {}).length > 0 || Object.keys(a.args.headers ?? {}).length > 0,
      enabled: true,
      status: remote && auth === "oauth" ? { kind: "sign_in_required" } : { kind: "starting" },
      url: a.args.url ?? null,
      auth,
    };
    servers.push(s);
    return delay(s);
  },
  sign_in_server: (a: { serverId: string }) => {
    const s = servers.find((x) => x.id === a.serverId)!;
    window.setTimeout(() => { s.status = { kind: "running", tool_count: 9 }; }, 1500);
    return delay("https://mcp.example.com/authorize?client_id=prism");
  },
  sign_out_server: (a: { serverId: string }) => { servers.find((x) => x.id === a.serverId)!.status = { kind: "sign_in_required" }; return delay(undefined); },
  remove_server: (a: { serverId: string }) => { servers.splice(servers.findIndex((s) => s.id === a.serverId), 1); return delay(undefined); },
  set_server_hook: (a: { serverId: string; hook: ServerHookConfig | null }) => {
    const s = servers.find((x) => x.id === a.serverId);
    if (s) s.hook = a.hook;
    return delay(s);
  },
  restart_server: () => delay(undefined),
  list_agents: () => delay(agents),
  create_manual_agent: (a: { name: string }) => {
    const id = crypto.randomUUID();
    agents.push({ id, name: a.name.trim(), client_name: a.name.trim(), client_version: null, status: "approved", created_at: iso(0), decided_at: iso(0), posture: "first_use", attention: "silent", client_id: null, connected: false, tokens: [{ kind: "manual", created_at: iso(0), expires_at: null }], clients: [] });
    return delay({ agent_id: id, token: `prism_demo_${crypto.randomUUID()}` });
  },
  replace_manual_token: (a: { agentId: string }) => {
    const agent = agents.find((x) => x.id === a.agentId);
    if (!agent || agent.client_id || agent.status !== "approved") return Promise.reject(new Error("Approve a manual client first."));
    agent.tokens = [{ kind: "manual", created_at: iso(0), expires_at: null }];
    return delay({ agent_id: agent.id, token: `prism_demo_${crypto.randomUUID()}` });
  },
  decide_agent: (a: { agentId: string; approve: boolean }) => { const ag = agents.find((x) => x.id === a.agentId); if (ag) { ag.status = a.approve ? "approved" : "denied"; ag.decided_at = iso(0); if (!a.approve) ag.tokens = []; } return delay(undefined); },
  revoke_agent_tokens: (a: { agentId: string }) => { const ag = agents.find((x) => x.id === a.agentId); if (ag) ag.tokens = []; return delay(undefined); },
  remove_agent: (a: { agentId: string }) => { agents.splice(agents.findIndex((x) => x.id === a.agentId), 1); return delay(undefined); },
  list_pending: () => delay(pending),
  list_signins: () => delay(signins),
  decide_signin: (a: { id: string }) => { signins = signins.filter((s) => s.id !== a.id); return delay(undefined); },
  decide: (a: { id: string; decision: Decision }) => {
    const call = pending.find((p) => p.id === a.id);
    pending = pending.filter((p) => p.id !== a.id);
    if (call) audit = [{ id: `e${Date.now()}`, at: iso(0), agent_id: call.agent_id, agent_name: call.agent_name, server_id: call.server_id, tool: call.tool, facets: call.facets, verdict: a.decision.verdict === "allow" ? "allowed" : "denied", source: { kind: "human" }, duration_ms: 400, error: null, attention: "silent" }, ...audit];
    if (call && a.decision.scope !== "once") {
      const target = a.decision.condition ? "tool" : a.decision.target ?? "tool";
      const minutes = typeof a.decision.scope === "object" ? a.decision.scope.for.minutes : null;
      rules = [...rules, { id: `r${Date.now()}`, agent_id: call.agent_id, server_id: target === "agent" ? null : call.server_id, tool: target === "tool" ? call.tool : null, condition: a.decision.condition, decision: a.decision.verdict, attention: null, scope: a.decision.scope === "session" ? "session" : "always", expires_at: minutes ? iso(-60 * minutes) : null, created_at: iso(0) }];
    }
    return delay(undefined);
  },
  list_rules: () => delay(rules.filter((r) => !r.expires_at || Date.parse(r.expires_at) > Date.now())),
  delete_rule: (a: { ruleId: string }) => { rules = rules.filter((r) => r.id !== a.ruleId); return delay(undefined); },
  add_rule: (a: { rule: NewRule }) => {
    const n = a.rule;
    rules = rules.filter((r) => !(r.agent_id === n.agent_id && r.server_id === n.server_id && r.tool === n.tool && r.condition == null));
    const rule: Rule = { id: `r${Date.now()}`, agent_id: n.agent_id, server_id: n.server_id, tool: n.tool, decision: n.decision, attention: n.attention ?? null, scope: n.scope ?? "always", expires_at: n.minutes ? iso(-60 * n.minutes) : null, created_at: iso(0) };
    rules = [...rules, rule];
    return delay(rule);
  },
  set_agent_policy: (a: { agentId: string; posture: AgentConfig["posture"] | null; attention: AgentConfig["attention"] | null }) => {
    const ag = agents.find((x) => x.id === a.agentId);
    if (!ag) return Promise.reject(new Error("mock: no such agent"));
    if (a.posture) ag.posture = a.posture;
    if (a.attention) ag.attention = a.attention;
    return delay(ag);
  },
  get_settings: () => delay(settings),
  retry_listener: () => { listener = { kind: "listening" }; return delay(undefined); },
  suggest_port: () => delay(listenPort + 1),
  set_listen_address: (a: { address: ListenAddress }) => { listenAddress = a.address; return delay(undefined); },
  set_listen_port: (a: { port: number }) => {
    if (a.port === 9090) return Promise.reject(new Error(`port ${a.port} is in use`));
    listenPort = a.port; listener = { kind: "listening" }; return delay(undefined);
  },
  set_settings: (a: { settings: Settings }) => { settings = { ...a.settings }; return delay(undefined); },
  list_server_tools: (a: { serverId: string }) => delay(tools[a.serverId] ?? []),
  set_tool_exposed: (a: { serverId: string; tool: string; exposed: boolean }) => {
    const tool = (tools[a.serverId] ?? []).find((x) => x.name === a.tool);
    if (tool) tool.exposed = a.exposed;
    const server = servers.find((x) => x.id === a.serverId);
    if (server) server.hidden_tools = (tools[a.serverId] ?? []).filter((x) => !x.exposed).map((x) => x.name);
    return delay(undefined);
  },
  list_audit: (a: {limit:number} & import("./state").ActivityFilter) => delay(mockQuery(a).entries.slice(0,a.limit)),
  list_audit_page: (a: {query: import("./state").ActivityFilter & {offset?:number; limit?:number}}) => {
    const result = mockQuery(a.query); const offset=a.query.offset ?? 0; const limit=a.query.limit ?? 100;
    return delay({...result, entries:result.entries.slice(offset,offset+limit), total:result.entries.length, offset, limit, has_more:offset+limit<result.entries.length});
  },
  get_activity: () => delay(activitySummary()),
  get_native_status: () => {
    const {entries, window} = mockQuery({nativeOnly:true});
    const reasons = (rows: AuditEntry[]) => [...new Set(rows.flatMap(e => e.native?.would_hold ? [e.native.would_hold] : []))].map(reason => ({reason, count:rows.filter(e => e.native?.would_hold === reason).length}));
    nativeStatus.window=window; nativeStatus.actions_7d=entries.length; nativeStatus.by_reason=reasons(entries); nativeStatus.would_hold_7d=entries.filter(needsAttention).length;
    for (const host of nativeStatus.hosts) { const rows=entries.filter(e => e.agent_id===`host:${host.host}`); host.actions_7d=rows.length; host.by_reason=reasons(rows); }
    return delay({...nativeStatus});
  },
  set_observe_native: (a: { on: boolean }) => { nativeStatus.observe_native = a.on; return delay(undefined); },
  rotate_hook_token: () => { for (const s of nativeStatus.setup) s.hook_installed = false; return delay(undefined); },
  get_host_hook_snippet: (a: { host: string }) => {
    const url = nativeStatus.hosts.find((h) => h.host === a.host)!.hook_url;
    const entry = a.host === "codex"
      ? { type: "command", command: `curl -s --connect-timeout 1 -m 3 -o /dev/null -X POST -H Content-Type:application/json --data-binary @- ${url}`, timeout: 5 }
      : { type: "http", url, timeout: 5 };
    return delay(JSON.stringify({ hooks: { PreToolUse: [{ hooks: [entry] }] } }, null, 2));
  },
  setup_harness: (a: { host: string }) => { const s = nativeStatus.setup.find((h) => h.host === a.host)!; s.setup_present = true; s.hook_installed = true; s.mcp_configured = true; s.events_received = false; return delay({paths: [s.settings_path, s.mcp_path], backups: [s.settings_path + ".bak"]}); },
  remove_harness_setup: (a: { host: string }) => { const s = nativeStatus.setup.find((h) => h.host === a.host)!; s.setup_present = false; s.hook_installed = false; s.mcp_configured = false; s.events_received = false; return delay({paths: [s.settings_path, s.mcp_path], backups: [s.settings_path + ".bak"]}); },
  install_host_hook: (a: { host: string }) => { const s = nativeStatus.setup.find((h) => h.host === a.host)!; s.hook_installed = true; return delay({ path: s.settings_path, backup: s.settings_path + ".bak" }); },
  export_native_report: () => delay({path:"/home/george/Downloads/prism-native.jsonl", metadata_path:"/home/george/Downloads/prism-native.metadata.json", total:mockQuery({nativeOnly:true,attention:true,days:30}).entries.length}),
  export_audit: (a: {query: import("./state").ActivityFilter}) =>
    delay({path:"/home/george/Downloads/prism-actions.jsonl", metadata_path:"/home/george/Downloads/prism-actions.metadata.json", total:mockQuery(a.query).entries.length}),
  open_export: (_a: {path: string}) => delay(undefined),
  open_audit_log: () => delay(undefined),
  hide_panel: () => delay(undefined),
  get_update_status: () =>
    delay({
      current: "0.2.0",
      available: { version: "0.3.0", current: "0.2.0", notes: "### Added\n- Built-in updater. Prism checks the latest release after launch and every six hours, and **Settings → Updates** installs it in place.\n\n### Fixed\n- Linux: the deb desktop entry had no category, so Cinnamon did not list Prism. It now sits under Development. See `prism.json` for the rest.", date: null, installable: true },
      checked_at: new Date().toISOString(),
      installable: true,
    }),
  check_update: () => delay({ version: "0.3.0", current: "0.2.0", notes: "### Added\n- Built-in updater. Prism checks the latest release after launch and every six hours, and **Settings → Updates** installs it in place.\n\n### Fixed\n- Linux: the deb desktop entry had no category, so Cinnamon did not list Prism. It now sits under Development. See `prism.json` for the rest.", date: null, installable: true }),
  install_update: () => delay(undefined),
  get_connect_snippet: (): Promise<ConnectSnippet> =>
    delay({
      url: "http://127.0.0.1:9086/mcp",
      mcp_json: JSON.stringify({ mcpServers: { prism: { url: "http://127.0.0.1:9086/mcp" } } }, null, 2),
      network_url: networkUrl(),
    }),
};
