import { useEffect, useRef, useState } from "preact/hooks";
import * as api from "../api";
import { persistExposure, serverPrimaryAction, toolExposureActions } from "../server-actions";
import { errorMessage, pop, servers, status, toolRevisions } from "../state";
import type { HookDirection, ServerHookConfig, ServerView, ToolInfo } from "../types";
import { Button, Chip, ConfirmButton, Label, REVEAL, Screen, Segmented, ShowMore, StatusText, Switch, describeError, useReveal } from "../ui";
import { authenticationGuidance, refreshServers, serverWhere, statusChip } from "./Servers";

/** One server as its own screen: what it is, which of its tools agents get, and the few things you can do to it. */
export function ServerScreen({ serverId }: { serverId: string }) {
  const server = servers.value.find((s) => s.id === serverId);
  const running = server?.status.kind === "running";
  const [tools, setTools] = useState<ToolInfo[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [updating, setUpdating] = useState<Set<string>>(new Set());
  const toolsRequest = useRef(0);
  const revision = toolRevisions.value[serverId] ?? 0;

  useEffect(() => {
    let current = true;
    const request = ++toolsRequest.current;
    if (!running) {
      setTools(null);
      return;
    }
    // Don't let an older list overwrite an optimistic mutation.
    if (updating.size > 0) return;
    api.listServerTools(serverId).then((result) => {
      if (current && request === toolsRequest.current) setTools(result);
    }).catch((err) => {
      if (current && request === toolsRequest.current) errorMessage.value = describeError(err);
    });
    return () => { current = false; };
  }, [serverId, running, revision, updating]);

  // Removed elsewhere, or removed here: the screen has nothing to show, so it leaves.
  const loaded = status.value !== null;
  useEffect(() => {
    if (loaded && !server) pop();
  }, [loaded, server]);

  const { rows, total, more } = useReveal(tools ?? [], REVEAL, serverId);
  if (!server) return <div class="screen pushed" />;

  const act = async (fn: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    try {
      await fn();
      await refreshServers();
    } catch (err) {
      errorMessage.value = describeError(err);
    } finally {
      setBusy(false);
    }
  };

  /** Only one write per target; a refresh failure cannot undo a confirmed save. */
  const expose = async (tool: ToolInfo, next: boolean) => {
    await toolExposureActions.run(JSON.stringify([serverId, tool.name]), async () => {
      const flip = (list: ToolInfo[] | null, value: boolean) => list?.map((t) => (t.name === tool.name ? { ...t, exposed: value } : t)) ?? null;
      // Invalidate reads immediately, before the disabled control re-renders.
      toolsRequest.current += 1;
      setUpdating((old) => new Set(old).add(tool.name));
      setTools((list) => flip(list, next));
      try {
        await persistExposure(
          () => api.setToolExposed(serverId, tool.name, next),
          refreshServers,
          () => setTools((list) => flip(list, tool.exposed)),
        );
      } catch (err) {
        errorMessage.value = describeError(err);
      } finally {
        setUpdating((old) => {
          const remaining = new Set(old);
          remaining.delete(tool.name);
          return remaining;
        });
      }
    });
  };

  const primary = serverPrimaryAction(server.auth, server.status.kind);
  const guidance = authenticationGuidance(server);
  const exposed = tools?.filter((t) => t.exposed).length ?? 0;
  const footer = (
    <>
      <ConfirmButton variant="danger" confirm="Remove?" busy={busy} onConfirm={() => void act(() => api.removeServer(server.id))}>
        Remove
      </ConfirmButton>
      {server.auth === "oauth" && running ? (
        <ConfirmButton variant="quiet" confirm="Sign out?" busy={busy} onConfirm={() => void act(() => api.signOutServer(server.id))}>
          Sign out
        </ConfirmButton>
      ) : null}
      {primary === "sign-in" ? (
        <Button variant="primary" busy={busy} onClick={() => void act(() => api.signInServer(server.id))}>Sign in</Button>
      ) : primary === "retry" ? (
        <Button variant="primary" busy={busy} onClick={() => void act(() => api.restartServer(server.id))}>Retry</Button>
      ) : (
        <Button busy={busy} onClick={() => void act(() => api.restartServer(server.id))}>Restart</Button>
      )}
    </>
  );

  return (
    <div class="screen pushed">
      <Screen footer={footer}>
        <div class="server-head">
          {statusChip(server)}
          <StatusText>{server.url ? "remote" : "local"}</StatusText>
          <span class="grow" />
          <span class="sub mono truncate" title={server.url ?? server.command}>{serverWhere(server)}</span>
        </div>
        {server.status.kind === "failed" ? <p class="hint danger">{server.status.error}</p> : null}
        {guidance ? <p class="hint danger">{guidance}</p> : null}

        <section class="section">
          <Label right={tools && tools.length > 0 ? <span>{exposed === tools.length ? "all exposed" : `${exposed} of ${tools.length} exposed`}</span> : null}>Tools</Label>
          {!running ? (
            <p class="hint">Tools appear once the server is running.</p>
          ) : tools === null ? null : tools.length === 0 ? (
            <p class="hint">No tools.</p>
          ) : (
            <div class="list">
              {rows.map((tool) => (
                <div class={`item ${tool.exposed ? "" : "hidden-tool"}`} key={tool.name}>
                  <div class="title">
                    <span class="truncate mono small">{tool.name}</span>
                    {tool.read_only ? <Chip tone="ok">Read</Chip> : null}
                    {tool.destructive ? <Chip tone="warn">Writes</Chip> : null}
                  </div>
                  <div class="side">
                    <Switch checked={tool.exposed} disabled={busy || updating.has(tool.name)} label={`Expose ${tool.name} to agents`} onChange={(next) => void expose(tool, next)} />
                  </div>
                  {tool.description ? <div class="sub truncate" title={tool.description}>{tool.description}</div> : null}
                </div>
              ))}
              <ShowMore shown={rows.length} total={total} size={REVEAL} onMore={more} />
            </div>
          )}
          {running && tools && tools.length > 0 ? <p class="hint">A hidden tool is not listed to any agent and cannot be called.</p> : null}
        </section>

        <HookSection server={server} busy={busy} onSave={async (hook) => {
          await act(async () => {
            const updated = await api.setServerHook(server.id, hook);
            servers.value = servers.value.map((s) => (s.id === updated.id ? updated : s));
          });
        }} />
      </Screen>
    </div>
  );
}

function HookSection({
  server,
  busy,
  onSave,
}: {
  server: ServerView;
  busy: boolean;
  onSave: (hook: ServerHookConfig | null) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [command, setCommand] = useState(server.hook?.command ?? "");
  const [args, setArgs] = useState((server.hook?.args ?? []).join(" "));
  const [direction, setDirection] = useState<HookDirection>(server.hook?.direction ?? "send");
  const [timeoutSecs, setTimeoutSecs] = useState(server.hook?.timeout_secs ?? 10);

  useEffect(() => {
    setCommand(server.hook?.command ?? "");
    setArgs((server.hook?.args ?? []).join(" "));
    setDirection(server.hook?.direction ?? "send");
    setTimeoutSecs(server.hook?.timeout_secs ?? 10);
  }, [server.hook]);

  const save = async () => {
    const trimmed = command.trim();
    if (!trimmed) {
      await onSave(null);
      setEditing(false);
      return;
    }
    const parsedArgs = args.trim() ? args.trim().split(/\s+/) : [];
    await onSave({
      command: trimmed,
      args: parsedArgs,
      direction,
      timeout_secs: Number(timeoutSecs) || 10,
    });
    setEditing(false);
  };

  const remove = async () => {
    await onSave(null);
    setEditing(false);
  };

  return (
    <section class="section">
      <Label right={server.hook ? <Chip tone="accent">{server.hook.direction}</Chip> : null}>
        Message Hook
      </Label>
      {!editing && server.hook ? (
        <div class="list">
          <div class="item">
            <div class="title">
              <span class="mono small truncate">
                {server.hook.command} {server.hook.args?.join(" ")}
              </span>
              <Chip>{server.hook.timeout_secs ?? 10}s</Chip>
            </div>
            <div class="side" style="display: flex; gap: 4px;">
              <Button variant="quiet" disabled={busy} onClick={() => setEditing(true)}>
                Edit
              </Button>
              <ConfirmButton
                variant="quiet"
                class="danger"
                confirm="Remove?"
                disabled={busy}
                onConfirm={() => void remove()}
              >
                Remove
              </ConfirmButton>
            </div>
          </div>
          <p class="hint">Subprocess intercepts raw JSON-RPC messages via stdin/stdout (rc=0 patch, rc=2 deny).</p>
        </div>
      ) : !editing ? (
        <div>
          <p class="hint">No subprocess hook configured for this server.</p>
          <Button variant="quiet" disabled={busy} onClick={() => setEditing(true)}>
            + Configure Hook
          </Button>
        </div>
      ) : (
        <div class="fields" style="margin-top: 8px;">
          <label class="field">
            <span>Executable / Command</span>
            <input
              class="input mono"
              placeholder="/path/to/hook.sh or python3"
              value={command}
              onInput={(e) => setCommand((e.currentTarget as HTMLInputElement).value)}
              disabled={busy}
            />
          </label>
          <label class="field">
            <span>Arguments</span>
            <input
              class="input mono"
              placeholder="e.g. -u /path/to/filter.py"
              value={args}
              onInput={(e) => setArgs((e.currentTarget as HTMLInputElement).value)}
              disabled={busy}
            />
          </label>
          <div class="field">
            <span>Traffic Direction</span>
            <Segmented
              small
              label="Direction"
              value={direction}
              options={[
                { value: "send", label: "Outgoing (Requests)" },
                { value: "recv", label: "Incoming (Responses)" },
                { value: "both", label: "Both" },
              ]}
              onChange={(next) => setDirection(next as HookDirection)}
            />
          </div>
          <label class="field">
            <span>Timeout</span>
            <input
              class="input mono"
              type="number"
              min={1}
              max={120}
              value={timeoutSecs}
              onInput={(e) => setTimeoutSecs(Number((e.currentTarget as HTMLInputElement).value) || 10)}
              disabled={busy}
            />
            <small>Seconds before hook is killed.</small>
          </label>
          <div style="display: flex; gap: 8px; margin-top: 8px;">
            <Button variant="primary" busy={busy} onClick={() => void save()}>
              Save Hook
            </Button>
            <Button variant="quiet" disabled={busy} onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
