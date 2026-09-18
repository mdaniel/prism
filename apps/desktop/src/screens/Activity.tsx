import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { LatestRequest } from "../latest-request";
import * as api from "../api";
import { FeedRow } from "../feed";
import { hostName } from "../hosts";
import { agents, audit, errorMessage, replace } from "../state";
import type { ActivityFilter } from "../state";
import type { AuditEntry, AuditPage } from "../types";
import { Button, Chip, CloseIcon, Label, REVEAL, Screen, Segmented, ShowMore, describeError } from "../ui";

/** Rows arrive in slices of this size from one snapshot. Each slice appends below the last; nothing shifts. */
const PAGE = REVEAL;

function dayText(day: string): string {
  return new Date(`${day}T12:00:00`).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

/** A stable view of the retained rows behind a count; incoming events never shift its pages. */
export function ActivityScreen({ filter }: { filter: ActivityFilter }) {
  // A filter change immediately clears rows, pagination, and export state together.
  return <ActivityPage key={JSON.stringify(filter)} filter={filter} />;
}

function ActivityPage({ filter }: { filter: ActivityFilter }) {
  /** The first slice: it fixes the snapshot and the total every later slice is read against. */
  const [page, setPage] = useState<AuditPage | null>(null);
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const requests = useRef(new LatestRequest());
  const [loading, setLoading] = useState(true);
  const latest = audit.value[0];
  useLayoutEffect(() => () => requests.current.invalidate(), []);
  useEffect(() => {
    void requests.current.run(() => api.listAuditPage(filter, 0, PAGE), p => {
      setPage(p);
      setRows(p.entries);
      setLoading(false);
    }, e => {
      setLoading(false);
      setFailed(true);
      errorMessage.value = describeError(e);
    });
    return () => requests.current.invalidate();
  }, []);
  useEffect(() => {
    if (saved === null) return;
    const timer = window.setTimeout(() => setSaved(null), 4000);
    return () => window.clearTimeout(timer);
  }, [saved]);
  /** The next slice reads against the snapshot the first one fixed, so retention cannot shift the rows above it. */
  const more = async () => {
    if (!page || loading || failed) return;
    setLoading(true);
    await requests.current.run(() => api.listAuditPage({...filter, at: page.window.snapshot_at}, rows.length, PAGE), p => {
      setLoading(false);
      if (p.total !== page.total) { setPage(null); setFailed(true); errorMessage.value = "Retained history changed. Refresh the log."; return; }
      setRows((shown) => [...shown, ...p.entries]);
    }, e => {
      setLoading(false);
      errorMessage.value = describeError(e);
    });
  };
  const exportRows = async () => {
    if (!page || busy) return;
    setBusy(true);
    try {
      const report = await api.exportAudit({...filter, at: page.window.snapshot_at});
      await api.openExport(report.path);
      setSaved(`Saved ${report.total} ${report.total === 1 ? "action" : "actions"} to Downloads.`);
    } catch (e) { errorMessage.value = describeError(e); }
    finally { setBusy(false); }
  };
  const openLog = async () => {
    try { await api.openAuditLog(); }
    catch (e) { errorMessage.value = describeError(e); }
  };
  const openMcpLog = async () => {
    try { await api.openMcpLog(); }
    catch (e) { errorMessage.value = describeError(e); }
  };
  const openMcpServersLog = async () => {
    try { await api.openMcpServersLog(); }
    catch (e) { errorMessage.value = describeError(e); }
  };
  const narrow = (patch: Partial<ActivityFilter>) => replace({ kind: "activity", ...filter, ...patch });
  const refresh = () => narrow({at: new Date().toISOString()});
  const agentName = filter.agentId ? (agents.value.find(a => a.id === filter.agentId)?.name ?? hostName(filter.agentId)) : null;
  const chips: { key: keyof ActivityFilter; text: string }[] = [
    ...(agentName ? [{ key: "agentId" as const, text: agentName }] : []),
    ...(filter.day ? [{ key: "day" as const, text: dayText(filter.day) }] : []),
    ...(filter.reason ? [{ key: "reason" as const, text: filter.reason.replace(/_/g, " ") }] : []),
    ...(filter.nativeOnly ? [{ key: "nativeOnly" as const, text: "Observed" }] : []),
  ];
  return <div class="screen pushed"><Screen log footer={
    <>
      <Button variant="quiet" onClick={() => void openLog()}>Open log</Button>
      <Button variant="quiet" onClick={() => void openMcpLog()}>Open MCP traffic</Button>
      <Button variant="quiet" onClick={() => void openMcpServersLog()}>Open servers traffic</Button>
      <Button busy={busy} disabled={!page || page.total === 0} onClick={() => void exportRows()}>Export</Button>
    </>
  }>
    <div class="section feed">
      <Label right={page ? <span>{page.total}</span> : null}>
        <Segmented small label="Which actions" value={filter.attention ? "attention" : "all"}
          options={[{value:"all", label:"All"}, {value:"attention", label:"Needed attention"}]}
          onChange={v => narrow({attention: v === "attention" ? true : undefined})} />
      </Label>
      <div class="history-controls">
        <select aria-label="History period" value={filter.days ?? 7} onChange={e => narrow({days: Number(e.currentTarget.value), day:undefined})}>
          <option value={7}>Last 7 days</option><option value={30}>Last 30 days</option>
        </select>
        <button type="button" class="link" onClick={refresh}>{latest && page && latest.at > page.window.snapshot_at ? "New actions · Refresh" : "Refresh"}</button>
      </div>
      {chips.length ? <div class="filters">{chips.map(c => <button type="button" class="filter" key={c.key} onClick={() => narrow({[c.key]: undefined})} title="Remove this filter"><Chip>{c.text}</Chip><CloseIcon /></button>)}</div> : null}
      <p class="hint">Retained events only · up to 30 days.</p>
      {saved ? <p class="hint" role="status">{saved}</p> : null}
      {failed ? <Button variant="quiet" onClick={refresh}>Retry history</Button> : page === null ? <div class="muted small">Loading…</div> : rows.length === 0 ? <div class="muted small">Nothing here.</div> : (
        <>
          {rows.map(entry => <FeedRow key={entry.id} entry={entry} />)}
          <ShowMore shown={rows.length} total={page.total} size={PAGE} busy={loading} onMore={() => void more()} />
        </>
      )}
    </div>
  </Screen></div>;
}
