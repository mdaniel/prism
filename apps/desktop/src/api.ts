import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { mock } from "./mock";
import type { ActivityFilter } from "./state";

const inTauri = "__TAURI_INTERNALS__" in window;

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (inTauri) return tauriInvoke<T>(cmd, args);
  const fn = (mock as Record<string, (a: unknown) => Promise<unknown>>)[cmd];
  if (!fn) return Promise.reject(new Error(`mock: no handler for ${cmd}`));
  return fn(args ?? {}) as Promise<T>;
}
import type {
  AgentConfig,
  ActivitySummary,
  AuditEntry,
  AuditPage,
  ExportReport,
  ConnectSnippet,
  Decision,
  Attention,
  GatewayStatus,
  HookInstallResult,
  HarnessChanges,
  HttpAuth,
  ListenAddress,
  NativeStatus,
  NewRule,
  PendingCall,
  PendingSignIn,
  Posture,
  Rule,
  ServerView,
  Settings,
  ToolInfo,
  UpdateInfo,
  UpdateStatus,
} from "./types";

export function getStatus() {
  return invoke<GatewayStatus>("get_status");
}

export function listServers() {
  return invoke<ServerView[]>("list_servers");
}

export interface AddServerArgs {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** Remote server endpoint. When set, command is ignored. */
  url?: string;
  auth?: HttpAuth;
  headers?: Record<string, string>;
}

export function addServer(args: AddServerArgs) {
  return invoke<ServerView>("add_server", { args });
}

export function removeServer(serverId: string) {
  return invoke<void>("remove_server", { serverId });
}

/** Starts a browser sign-in for an OAuth server. The desktop opens the URL; it is also returned. */
export function signInServer(serverId: string) {
  return invoke<string>("sign_in_server", { serverId });
}

export function signOutServer(serverId: string) {
  return invoke<void>("sign_out_server", { serverId });
}

export function restartServer(serverId: string) {
  return invoke<void>("restart_server", { serverId });
}

export function listAgents() {
  return invoke<AgentConfig[]>("list_agents");
}

export function decideAgent(agentId: string, approve: boolean) {
  return invoke<void>("decide_agent", { agentId, approve });
}

export function removeAgent(agentId: string) {
  return invoke<void>("remove_agent", { agentId });
}

export function listSignins() {
  return invoke<PendingSignIn[]>("list_signins");
}

export function decideSignin(id: string, approve: boolean) {
  return invoke<void>("decide_signin", { id, approve });
}

/** Sign an agent out everywhere: every token it holds stops working at once. */
export function revokeAgentTokens(agentId: string) {
  return invoke<void>("revoke_agent_tokens", { agentId });
}

/** Forget one client registration and its tokens; the agent and its other clients stay. */
export function forgetClient(agentId: string, clientId: string) {
  return invoke<void>("forget_client", { agentId, clientId });
}

export function listPending() {
  return invoke<PendingCall[]>("list_pending");
}

export function decide(id: string, decision: Decision) {
  return invoke<void>("decide", { id, decision });
}

export function listRules() {
  return invoke<Rule[]>("list_rules");
}

export function deleteRule(ruleId: string) {
  return invoke<void>("delete_rule", { ruleId });
}

export function addRule(rule: NewRule) {
  return invoke<Rule>("add_rule", { rule });
}

export function setAgentPolicy(agentId: string, policy: { posture?: Posture; attention?: Attention }) {
  return invoke<AgentConfig>("set_agent_policy", { agentId, posture: policy.posture ?? null, attention: policy.attention ?? null });
}

export function getSettings() {
  return invoke<Settings>("get_settings");
}

export function setSettings(settings: Settings) {
  return invoke<void>("set_settings", { settings });
}

/** Try the configured port again after a clash. */
export function retryListener() {
  return invoke<void>("retry_listener");
}

/** A free port near the configured one, offered when the configured one is taken. */
export function suggestPort() {
  return invoke<number | null>("suggest_port");
}

/** Move the listener. Agents keep their tokens but need the new address. */
export function setListenPort(port: number) {
  return invoke<void>("set_listen_port", { port });
}

/** Loopback only, or every interface so agents on other machines can connect. */
export function setListenAddress(address: ListenAddress) {
  return invoke<void>("set_listen_address", { address });
}

export function listServerTools(serverId: string) {
  return invoke<ToolInfo[]>("list_server_tools", { serverId });
}

/** Show or hide one tool of a server for every agent. */
export function setToolExposed(serverId: string, tool: string, exposed: boolean) {
  return invoke<void>("set_tool_exposed", { serverId, tool, exposed });
}

export function listAudit(limit = 20, filter: ActivityFilter = {}) {
  return invoke<AuditEntry[]>("list_audit", {
    limit,
    agentId: filter.agentId ?? null,
    attention: filter.attention ?? null,
    day: filter.day ?? null,
    reason: filter.reason ?? null,
  });
}

export function getActivity(days = 7) {
  return invoke<ActivitySummary>("get_activity", { days });
}

export function hidePanel() {
  return invoke<void>("hide_panel");
}

export function getConnectSnippet() {
  return invoke<ConnectSnippet>("get_connect_snippet");
}

export function createManualAgent(name: string) {
  return invoke<import("./types").ManualToken>("create_manual_agent", { name });
}

export function replaceManualToken(agentId: string) {
  return invoke<import("./types").ManualToken>("replace_manual_token", { agentId });
}

export function getUpdateStatus() {
  return invoke<UpdateStatus>("get_update_status");
}

export function checkUpdate() {
  return invoke<UpdateInfo | null>("check_update");
}

export function installUpdate() {
  return invoke<void>("install_update");
}

export function getNativeStatus() {
  return invoke<NativeStatus>("get_native_status");
}

export function setObserveNative(on: boolean) {
  return invoke<void>("set_observe_native", { on });
}

export function rotateHookToken() {
  return invoke<void>("rotate_hook_token");
}

export function getHostHookSnippet(host: string) {
  return invoke<string>("get_host_hook_snippet", { host });
}

export function installHostHook(host: string) {
  return invoke<HookInstallResult>("install_host_hook", { host });
}

/** Writes the would-have-asked entries to Downloads and returns the path. */
export function exportNativeReport() {
  return invoke<ExportReport>("export_native_report");
}

export function setupHarness(host: string) { return invoke<HarnessChanges>("setup_harness", { host }); }
export function removeHarnessSetup(host: string) { return invoke<HarnessChanges>("remove_harness_setup", { host }); }

export function listAuditPage(filter: ActivityFilter, offset = 0, limit = 100) {
  return invoke<AuditPage>("list_audit_page", {query: {...filter, offset, limit}});
}

/** Writes exactly the rows the filtered log holds to Downloads and returns the path. */
export function exportAudit(filter: ActivityFilter) {
  return invoke<ExportReport>("export_audit", {query: {...filter}});
}

/** Opens an export Prism wrote. The host re-checks the path before opening it. */
export function openExport(path: string) {
  return invoke<void>("open_export", { path });
}

export function openAuditLog() {
  return invoke<void>("open_audit_log");
}

export function openMcpLog() {
  return invoke<void>("open_mcp_log");
}

export function openMcpServersLog() {
  return invoke<void>("open_mcp_servers_log");
}
