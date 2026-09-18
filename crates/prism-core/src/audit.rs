use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Local, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::config::{Attention, Posture};
use crate::error::{Error, Result};
use crate::events::{EventSender, GatewayEvent};

// The active file plus three archives retain at most 20 MiB, and at most 30 days.
// Busy installations can therefore retain substantially less than 30 days.
pub const MAX_QUERY_LIMIT: usize = 5000;
const MAX_PENDING_RECORDS: usize = 256;
const ARCHIVES: usize = 3;
const RETENTION_DAYS: i64 = 30;
pub const REDACTED_ERROR: &str = "Error details omitted to protect credentials";

/// How a call was resolved.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditVerdict {
    Allowed,
    Denied,
    Timeout,
    Error,
}

/// Who or what produced the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditSource {
    Rule {
        rule_id: String,
    },
    Human,
    Tripwire,
    /// The caller disconnected or cancelled the in-flight request.
    Cancelled,
    Timeout,
    /// The agent has not been approved in the panel yet.
    Unapproved,
    /// No rule matched; the agent's posture decided.
    Posture {
        posture: Posture,
    },
    /// Do-not-disturb was on, so the call resolved by the timeout behaviour without a hold.
    DoNotDisturb,
    /// A native action reported by an agent host's hook. Recorded, never decided.
    Observed,
}

/// What the record keeps about a native action beyond the tool name. `subject` is one redacted
/// line (a command, a path, an origin); the raw tool input is never stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeDetail {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub subject: String,
    /// Shadow deny-list rule id this action would have tripped. Nothing was held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub would_hold: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// An MCP tool Prism itself serves, seen again through the host's hook.
    #[serde(default)]
    pub via_prism: bool,
}

/// One audited tool-call attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: String,
    pub at: DateTime<Utc>,
    pub agent_id: String,
    pub agent_name: String,
    pub server_id: String,
    pub tool: String,
    pub verdict: AuditVerdict,
    pub source: AuditSource,
    pub duration_ms: u64,
    pub error: Option<String>,
    /// How loudly the desktop should surface this entry. Silent for anything a human already saw.
    #[serde(default)]
    pub attention: Attention,
    /// Present for native actions observed through a host hook; absent for MCP calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeDetail>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facets: Vec<String>,
}

/// Filters apply before pagination. Calendar days use the gateway's local timezone, exactly
/// like activity summaries. `reason` is the native shadow rule id, not an MCP verdict/source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditQuery {
    pub days: u32,
    /// Reuse a summary/page snapshot timestamp to freeze the event-time window. Retention
    /// remains live and can remove entries; this is not a durable cursor or pinned snapshot.
    #[serde(alias = "snapshotAt")]
    pub at: Option<DateTime<Utc>>,
    #[serde(alias = "agentId")]
    pub agent_id: Option<String>,
    pub attention: Option<bool>,
    pub day: Option<NaiveDate>,
    pub reason: Option<String>,
    #[serde(alias = "nativeOnly")]
    pub native_only: bool,
    #[serde(alias = "includeViaPrism")]
    pub include_via_prism: bool,
    pub offset: usize,
    pub limit: usize,
    /// Internal presentation context: configured manual identities must never be grouped by
    /// their display name. Gateway supplies this independently of untrusted query JSON.
    #[serde(skip)]
    pub canonicalization_exclusions: HashSet<String>,
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            days: 7,
            at: None,
            agent_id: None,
            attention: None,
            day: None,
            reason: None,
            native_only: false,
            include_via_prism: false,
            offset: 0,
            limit: 100,
            canonicalization_exclusions: HashSet::new(),
        }
    }
}

/// Retention is a ceiling, not a guarantee of continuous coverage. The earliest retained
/// event does not prove that events before it were absent, even if no archive is currently full.
#[derive(Debug, Clone, Serialize)]
pub struct AuditWindow {
    pub days: u32,
    pub first_day: NaiveDate,
    pub last_day: NaiveDate,
    pub snapshot_at: DateTime<Utc>,
    /// The actual read time and age cutoff can advance while `snapshot_at` stays fixed.
    pub read_at: DateTime<Utc>,
    pub retention_cutoff_at: DateTime<Utc>,
    pub retention_may_remove_entries: bool,
    pub oldest_available_at: Option<DateTime<Utc>>,
    pub newest_available_at: Option<DateTime<Utc>>,
    pub retention_days: u32,
    pub archive_count: usize,
    pub max_file_bytes: u64,
    pub max_history_bytes: u64,
    pub retained_bytes: u64,
    pub size_limited: bool,
    /// Always false: size rotation or a period when Prism was stopped can leave gaps.
    pub full_window_guaranteed: bool,
}

impl AuditWindow {
    pub(crate) fn new(days: u32, now: DateTime<Utc>) -> Self {
        let days = days.clamp(1, RETENTION_DAYS as u32);
        let last_day = now.with_timezone(&Local).date_naive();
        Self {
            days,
            first_day: last_day - chrono::Duration::days(i64::from(days) - 1),
            last_day,
            snapshot_at: now,
            read_at: now,
            retention_cutoff_at: now - chrono::Duration::days(RETENTION_DAYS),
            retention_may_remove_entries: true,
            oldest_available_at: None,
            newest_available_at: None,
            retention_days: RETENTION_DAYS as u32,
            archive_count: ARCHIVES,
            max_file_bytes: u64::MAX,
            max_history_bytes: u64::MAX,
            retained_bytes: 0,
            size_limited: false,
            full_window_guaranteed: false,
        }
    }

    pub(crate) fn contains(&self, entry: &AuditEntry) -> bool {
        let date = entry.at.with_timezone(&Local).date_naive();
        date >= self.first_day
            && date <= self.last_day
            && entry.at <= self.snapshot_at
            && entry.at >= self.retention_cutoff_at
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    /// Number of matching retained entries before pagination.
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
    pub window: AuditWindow,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditExport {
    pub jsonl: String,
    pub total: usize,
    pub window: AuditWindow,
}

/// Presentation-only grouping of historical registrations using the supported harness mapping.
/// This is never an authenticated identity and must not replace `AuditEntry::agent_id` on disk,
/// in events, or in exports. Explicit host ids retain their origin; unknown clients keep their ids.
/// Gateway calls also exclude known manual identities using the current registration config.
pub fn canonical_agent_id(entry: &AuditEntry) -> Cow<'_, str> {
    if let Some(host_id) = entry.agent_id.strip_prefix("host:") {
        let (host, origin) = host_id
            .split_once('@')
            .map_or((host_id, None), |(h, o)| (h, Some(o)));
        return match crate::native::harness_for_client_name(host) {
            Some(host) => Cow::Owned(crate::native::harness_agent_id(host, origin)),
            None => Cow::Borrowed(&entry.agent_id),
        };
    }
    let host = entry
        .native
        .as_ref()
        .and_then(|native| crate::native::harness_for_client_name(&native.host))
        .or_else(|| crate::native::harness_for_client_name(&entry.agent_name));
    match host {
        Some(host) => Cow::Owned(crate::native::harness_agent_id(host, None)),
        None => Cow::Borrowed(&entry.agent_id),
    }
}

pub(crate) fn canonical_agent_id_excluding<'a>(
    entry: &'a AuditEntry,
    exclusions: &HashSet<String>,
) -> Cow<'a, str> {
    if exclusions.contains(&entry.agent_id) {
        Cow::Borrowed(&entry.agent_id)
    } else {
        canonical_agent_id(entry)
    }
}

impl AuditQuery {
    pub(crate) fn matches(&self, entry: &AuditEntry, window: &AuditWindow) -> bool {
        window.contains(entry)
            && (self.include_via_prism || !entry.native.as_ref().is_some_and(|n| n.via_prism))
            && self.agent_id.as_ref().is_none_or(|id| {
                id == &entry.agent_id
                    || canonical_agent_id_excluding(entry, &self.canonicalization_exclusions)
                        .as_ref()
                        == id
            })
            && self
                .attention
                .is_none_or(|attention| crate::activity::needs_attention(entry) == attention)
            && self
                .day
                .is_none_or(|day| entry.at.with_timezone(&Local).date_naive() == day)
            && (!self.native_only || entry.native.is_some())
            && self.reason.as_ref().is_none_or(|reason| {
                entry
                    .native
                    .as_ref()
                    .and_then(|native| native.would_hold.as_ref())
                    == Some(reason)
            })
    }
}

/// Cached, private, redacted JSONL history. Cache and writer share a lock: a snapshot sees
/// either side of an append/rotation/retention operation, never a mixture of their files.
#[derive(Clone)]
pub struct AuditLog {
    path: PathBuf,
    writer: Arc<Mutex<AuditWriter>>,
    pending: Arc<Mutex<VecDeque<AuditEntry>>>,
    drain_lock: Arc<Mutex<()>>,
    scheduled: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    events: EventSender,
}

struct AuditWriter {
    file: Option<File>,
    bytes: u64,
    cleaned_at: Instant,
    history: HistoryCache,
    /// A failed append can leave a partial line. Never silently serve plausible counts after it.
    failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    bytes: u64,
    modified: SystemTime,
    created: Option<SystemTime>,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Default)]
struct HistoryCache {
    // Active file first, oldest archive last. Entries in each segment are in write order.
    segments: Vec<Vec<Arc<AuditEntry>>>,
    stamps: Vec<Option<FileStamp>>,
    sorted: Option<Arc<Vec<Arc<AuditEntry>>>>,
}

pub(crate) struct AuditSnapshot {
    pub entries: Arc<Vec<Arc<AuditEntry>>>,
    pub window: AuditWindow,
}

fn history_error(message: &str) -> std::io::Error {
    std::io::Error::other(message)
}

fn history_paths(path: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    (0..=ARCHIVES).map(|index| {
        if index == 0 {
            path.to_path_buf()
        } else {
            archive(path, index)
        }
    })
}

fn file_stamp(path: &Path) -> std::io::Result<Option<FileStamp>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if !metadata.is_file() {
        return Err(history_error("audit history is not a regular file"));
    }
    Ok(Some(FileStamp {
        bytes: metadata.len(),
        modified: metadata.modified()?,
        created: metadata.created().ok(),
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
    }))
}

impl HistoryCache {
    fn load(path: &Path) -> std::io::Result<Self> {
        let mut cache = Self::default();
        for path in history_paths(path) {
            let stamp = file_stamp(&path)?;
            let mut entries = Vec::new();
            if let Some(stamp) = &stamp {
                let mut reader = BufReader::new(crate::storage::read(&path)?);
                let mut bytes = 0;
                loop {
                    let mut line = Vec::new();
                    let read = (&mut reader).read_until(b'\n', &mut line)?;
                    if read == 0 {
                        break;
                    }
                    bytes += read as u64;
                    if line.last() != Some(&b'\n') {
                        return Err(history_error(
                            "audit history contains an incomplete record",
                        ));
                    }
                    let mut entry: AuditEntry = serde_json::from_slice(&line).map_err(|_| {
                        history_error("audit history contains an unreadable record")
                    })?;
                    sanitize(&mut entry);
                    entries.push(Arc::new(entry));
                }
                if bytes != stamp.bytes || file_stamp(&path)?.as_ref() != Some(stamp) {
                    return Err(history_error("audit history changed while being read"));
                }
            }
            cache.segments.push(entries);
            cache.stamps.push(stamp);
        }
        Ok(cache)
    }

    fn refresh(&mut self, path: &Path) -> std::io::Result<bool> {
        let stamps = history_paths(path)
            .map(|path| file_stamp(&path))
            .collect::<std::io::Result<Vec<_>>>()?;
        if stamps != self.stamps {
            // A missing formerly retained file is a read failure, not an empty window. Only our
            // own rotation/cleanup may remove segments and update their stamps together.
            if stamps
                .iter()
                .zip(&self.stamps)
                .any(|(now, before)| now.is_none() && before.is_some())
            {
                return Err(history_error("a retained audit file is missing"));
            }
            *self = Self::load(path)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn snapshot(&mut self, days: u32, at: DateTime<Utc>, now: DateTime<Utc>) -> AuditSnapshot {
        let entries = self
            .sorted
            .get_or_insert_with(|| {
                // Stable sort gives later writes precedence when timestamps are equal.
                let mut entries: Vec<_> = self
                    .segments
                    .iter()
                    .flat_map(|segment| segment.iter().rev().cloned())
                    .collect();
                entries.sort_by_key(|entry| std::cmp::Reverse(entry.at));
                Arc::new(entries)
            })
            .clone();
        let mut window = AuditWindow::new(days, at);
        let cutoff = now - chrono::Duration::days(RETENTION_DAYS);
        window.read_at = now;
        window.retention_cutoff_at = cutoff;
        let mut available = entries
            .iter()
            .filter(|entry| entry.at >= cutoff && entry.at <= at);
        window.newest_available_at = available.next().map(|entry| entry.at);
        window.oldest_available_at = available
            .next_back()
            .map(|entry| entry.at)
            .or(window.newest_available_at);
        window.retained_bytes = self.stamps.iter().flatten().map(|stamp| stamp.bytes).sum();
        AuditSnapshot { entries, window }
    }
}

fn archive(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn sanitize(entry: &mut AuditEntry) {
    // Raw backend errors may echo arguments, URLs, tokens, or complete response bodies.
    // Omit them instead of relying on a list of recognizable secret formats.
    if entry.error.is_some() {
        entry.error = Some(REDACTED_ERROR.into());
    }
    for value in [
        &mut entry.id,
        &mut entry.agent_name,
        &mut entry.tool,
        &mut entry.agent_id,
        &mut entry.server_id,
    ] {
        *value = value.chars().take(512).collect();
    }
    entry.facets.truncate(4);
    for facet in &mut entry.facets {
        *facet = facet
            .chars()
            .filter(|c| !c.is_control())
            .take(512)
            .collect();
    }
    if let AuditSource::Rule { rule_id } = &mut entry.source {
        *rule_id = rule_id.chars().take(512).collect();
    }
    if let Some(native) = entry.native.as_mut() {
        for value in [&mut native.host, &mut native.subject] {
            *value = value.chars().take(512).collect();
        }
        for value in [
            &mut native.session,
            &mut native.cwd,
            &mut native.would_hold,
            &mut native.agent_type,
        ]
        .into_iter()
        .flatten()
        {
            *value = value.chars().take(512).collect();
        }
    }
}

fn retain_file(path: &Path, now: DateTime<Utc>) -> std::io::Result<()> {
    if !path.try_exists()? {
        return Ok(());
    }
    let file = crate::storage::read(path)?;
    let mut reader = BufReader::new(file);
    let cutoff = now - chrono::Duration::days(RETENTION_DAYS);
    let mut retained = VecDeque::new();
    loop {
        let mut line = Vec::new();
        let read = (&mut reader).read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        let mut entry = serde_json::from_slice::<AuditEntry>(&line)
            .map_err(|_| history_error("audit history contains an unreadable record"))?;
        if entry.at < cutoff {
            continue;
        }
        sanitize(&mut entry);
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        retained.push_back(line);
    }
    drop(reader);
    crate::storage::atomic_write(path, &retained.into_iter().flatten().collect::<Vec<_>>())
}

fn maintain(path: &Path) -> std::io::Result<()> {
    let now = Utc::now();
    for index in 0..=ARCHIVES {
        let file = if index == 0 {
            path.to_path_buf()
        } else {
            archive(path, index)
        };
        retain_file(&file, now)?;
        if index != 0 && file.try_exists()? && fs::metadata(&file)?.len() == 0 {
            fs::remove_file(file)?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn rotate(path: &Path) -> std::io::Result<()> {
    for index in (1..=ARCHIVES).rev() {
        let target = archive(path, index);
        let source = if index == 1 {
            path.to_path_buf()
        } else {
            archive(path, index - 1)
        };
        crate::storage::prepare(&target)?;
        if target.try_exists()? {
            fs::remove_file(&target)?;
        }
        if source.try_exists()? {
            crate::storage::protect(&source)?;
            fs::rename(source, target)?;
        }
    }
    Ok(())
}

impl AuditLog {
    /// Synchronous startup/maintenance API; async callers must use a blocking worker.
    pub fn new(path: impl AsRef<Path>, events: EventSender) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let setup = (|| -> std::io::Result<AuditWriter> {
            crate::storage::prepare(&path)?;
            // Validate every retained file before rewriting any of them. In particular, a crash
            // tail stays byte-for-byte recoverable, even when another archive needs redaction.
            HistoryCache::load(&path)?;
            maintain(&path)?;
            let file = crate::storage::append(&path)?;
            let bytes = file.metadata()?.len();
            let history = HistoryCache::load(&path)?;
            Ok(AuditWriter {
                file: Some(file),
                bytes,
                cleaned_at: Instant::now(),
                history,
                failure: None,
            })
        })();
        let writer = setup.unwrap_or_else(|err| {
            error!(%err, "audit history unavailable; preserving files and suspending audit writes");
            AuditWriter {
                file: None,
                bytes: 0,
                cleaned_at: Instant::now(),
                history: HistoryCache::default(),
                failure: Some(format!(
                    "audit history unavailable; writes suspended: {err}"
                )),
            }
        });
        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(writer)),
            pending: Arc::new(Mutex::new(VecDeque::new())),
            drain_lock: Arc::new(Mutex::new(())),
            scheduled: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicBool::new(false)),
            events,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Release the file handle before a stopped gateway's next retention rewrite on Windows.
    pub(crate) fn close(&self) {
        self.drain_pending();
        if let Ok(mut writer) = self.writer.lock() {
            writer.file.take();
        }
    }

    pub(crate) fn cleanup(&self) -> std::io::Result<()> {
        self.drain_pending();
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| history_error("audit writer lock poisoned"))?;
        if let Some(failure) = &writer.failure {
            return Err(history_error(failure));
        }
        writer.file.take();
        let result = (|| {
            maintain(&self.path)?;
            let file = crate::storage::append(&self.path)?;
            writer.bytes = file.metadata()?.len();
            writer.file = Some(file);
            writer.history = HistoryCache::load(&self.path)?;
            writer.cleaned_at = Instant::now();
            Ok(())
        })();
        if let Err(ref err) = result {
            writer.failure = Some(format!("audit retention failed: {err}"));
        }
        result
    }

    /// Synchronous call sites (including cancellation guards) enqueue bounded, sanitized work.
    /// Async runtimes never perform the disk append/rotation themselves. Queries drain accepted
    /// writes first, so a record followed by a query observes that record even if the worker waits.
    pub fn record(&self, mut entry: AuditEntry) {
        sanitize(&mut entry);
        let start = {
            let mut pending = self.pending.lock().expect("audit pending lock poisoned");
            if pending.len() >= MAX_PENDING_RECORDS {
                if !self.dropped.swap(true, Ordering::AcqRel) {
                    error!("audit write queue is full; retained history is incomplete");
                }
                return;
            }
            pending.push_back(entry);
            !self.scheduled.swap(true, Ordering::AcqRel)
        };
        if start {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let audit = self.clone();
                runtime.spawn_blocking(move || audit.drain_pending());
            } else {
                self.drain_pending();
            }
        }
    }

    fn drain_pending(&self) {
        let _drain = self.drain_lock.lock().expect("audit drain lock poisoned");
        loop {
            let entry = {
                let mut pending = self.pending.lock().expect("audit pending lock poisoned");
                let entry = pending.pop_front();
                if entry.is_none() {
                    self.scheduled.store(false, Ordering::Release);
                }
                entry
            };
            let Some(entry) = entry else {
                break;
            };
            self.record_now(entry);
        }
    }

    fn record_now(&self, entry: AuditEntry) {
        let result = (|| -> std::io::Result<()> {
            let mut writer = self
                .writer
                .lock()
                .map_err(|_| history_error("audit writer lock poisoned"))?;
            if let Some(failure) = &writer.failure {
                return Err(history_error(failure));
            }
            let result = (|| {
                if writer.history.refresh(&self.path)? {
                    // An external replacement invalidates the open append handle as well.
                    writer.file.take();
                }
                let line = serde_json::to_string(&entry)?;
                self.append_line(&mut writer, &line)?;
                writer.history.segments[0].push(Arc::new(entry.clone()));
                writer.history.stamps[0] = file_stamp(&self.path)?;
                writer.history.sorted = None;
                Ok(())
            })();
            if let Err(ref err) = result {
                writer.failure = Some(format!("audit append failed: {err}"));
            }
            result
        })();
        if let Err(err) = result {
            error!(%err, "failed to append private audit log");
        }
        let _ = self.events.send(GatewayEvent::Audit(entry));
    }

    fn append_line(&self, writer: &mut AuditWriter, line: &str) -> std::io::Result<()> {
        if writer.cleaned_at.elapsed() >= Duration::from_secs(60 * 60) {
            writer.file.take();
            maintain(&self.path)?;
            writer.history = HistoryCache::load(&self.path)?;
            writer.cleaned_at = Instant::now();
        }
        if writer.file.is_none() {
            let file = crate::storage::append(&self.path)?;
            writer.bytes = file.metadata()?.len();
            writer.file = Some(file);
        }
        writeln!(writer.file.as_mut().expect("opened audit log"), "{line}")?;
        writer.bytes += line.len() as u64 + 1;
        Ok(())
    }

    /// Compatibility cache-only feed. Counts, filtered queries and exports must use `query`,
    /// which validates the retained files and reports storage failures to the caller.
    pub fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.drain_pending();
        let mut writer = self.writer.lock().expect("audit writer lock poisoned");
        let now = Utc::now();
        let snapshot = writer.history.snapshot(RETENTION_DAYS as u32, now, now);
        let query = AuditQuery {
            days: RETENTION_DAYS as u32,
            ..Default::default()
        };
        snapshot
            .entries
            .iter()
            .filter(|entry| query.matches(entry, &snapshot.window))
            .take(limit)
            .map(|entry| entry.as_ref().clone())
            .collect()
    }

    /// Retained reads, sorting, filtering and JSON serialization all run on the blocking pool.
    /// The immutable snapshot releases the writer lock before aggregation/export work begins.
    pub(crate) async fn read<T: Send + 'static>(
        &self,
        days: u32,
        read: impl FnOnce(AuditSnapshot) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.read_at(days, None, read).await
    }

    async fn read_at<T: Send + 'static>(
        &self,
        days: u32,
        at: Option<DateTime<Utc>>,
        read: impl FnOnce(AuditSnapshot) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let audit = self.clone();
        tokio::task::spawn_blocking(move || {
            audit.drain_pending();
            if audit.dropped.load(Ordering::Acquire) {
                return Err(Error::Io(history_error(
                    "audit write queue overflowed; retained history is incomplete",
                )));
            }
            let snapshot = {
                let mut writer = audit
                    .writer
                    .lock()
                    .map_err(|_| history_error("audit writer lock poisoned"))?;
                if let Some(failure) = &writer.failure {
                    return Err(Error::Io(history_error(failure)));
                }
                if writer.history.refresh(&audit.path)? {
                    writer.file.take();
                }
                let now = Utc::now();
                let at = at.unwrap_or(now);
                if at > now || at < now - chrono::Duration::days(RETENTION_DAYS) {
                    return Err(Error::Invalid("audit snapshot timestamp must be within retained time and not in the future".into()));
                }
                writer.history.snapshot(days, at, now)
            };
            read(snapshot)
        })
        .await
        .map_err(|_| Error::Gateway("audit history read could not complete".into()))?
    }

    pub async fn query(&self, query: AuditQuery) -> Result<AuditPage> {
        self.read_at(query.days, query.at, move |snapshot| {
            let limit = query.limit.min(MAX_QUERY_LIMIT);
            let mut total = 0usize;
            let mut entries = Vec::new();
            for entry in snapshot
                .entries
                .iter()
                .filter(|entry| query.matches(entry, &snapshot.window))
            {
                if total >= query.offset && entries.len() < limit {
                    entries.push(entry.as_ref().clone());
                }
                total += 1;
            }
            Ok(AuditPage {
                has_more: query.offset.saturating_add(entries.len()) < total,
                entries,
                total,
                offset: query.offset,
                limit,
                window: snapshot.window,
            })
        })
        .await
    }

    /// Export every matching retained entry; offset/limit apply to pages only.
    pub async fn export(&self, query: AuditQuery) -> Result<AuditExport> {
        self.read_at(query.days, query.at, move |snapshot| {
            let mut jsonl = String::new();
            let mut total = 0;
            for entry in snapshot
                .entries
                .iter()
                .filter(|entry| query.matches(entry, &snapshot.window))
            {
                jsonl.push_str(&serde_json::to_string(entry.as_ref())?);
                jsonl.push('\n');
                total += 1;
            }
            Ok(AuditExport {
                jsonl,
                total,
                window: snapshot.window,
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: DateTime<Utc>, id: &str) -> AuditEntry {
        AuditEntry {
            id: id.into(),
            at,
            agent_id: "a".into(),
            agent_name: "agent".into(),
            server_id: "s".into(),
            tool: "read".into(),
            verdict: AuditVerdict::Error,
            source: AuditSource::Human,
            duration_ms: 1,
            error: Some("Bearer secret-token password=hidden".into()),
            attention: Attention::Silent,
            native: None,
            facets: Vec::new(),
        }
    }

    #[test]
    fn reopening_refills_the_ring_from_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (events, _) = crate::events::channel();
        {
            let audit = AuditLog::new(&path, events.clone()).unwrap();
            audit.record(entry(Utc::now() - chrono::Duration::minutes(2), "older"));
            audit.record(entry(Utc::now(), "newer"));
        }
        let audit = AuditLog::new(&path, events).unwrap();
        let ids: Vec<String> = audit.list(10).into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["newer".to_string(), "older".to_string()]);
    }

    #[test]
    fn redacts_legacy_and_new_errors_and_expires_old_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let old = entry(Utc::now() - chrono::Duration::days(31), "expired");
        let recent = entry(Utc::now(), "retained");
        let bytes = format!(
            "{}\n{}\n",
            serde_json::to_string(&old).unwrap(),
            serde_json::to_string(&recent).unwrap()
        );
        fs::write(&path, &bytes).unwrap();
        fs::write(archive(&path, 1), &bytes).unwrap();
        let (events, _) = crate::events::channel();
        let audit = AuditLog::new(&path, events).unwrap();
        audit.record(entry(Utc::now(), "new"));
        for path in [&path, &archive(&path, 1)] {
            let text = fs::read_to_string(path).unwrap();
            assert!(!text.contains("secret-token"));
            assert!(!text.contains("hidden"));
            assert!(!text.contains("expired"));
            assert!(text.contains("retained"));
        }
        assert_eq!(audit.list(1)[0].error.as_deref(), Some(REDACTED_ERROR));
        // Age retention works while the application remains open, even without new calls.
        audit.record(old);
        audit.cleanup().unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("expired"));
        assert!(audit.list(10).iter().all(|entry| entry.id != "expired"));
    }

    fn native_entry(
        at: DateTime<Utc>,
        id: &str,
        host: &str,
        reason: Option<&str>,
        duplicate: bool,
    ) -> AuditEntry {
        let mut entry = entry(at, id);
        entry.agent_id = format!("old-{host}");
        entry.agent_name = crate::native::harness_display_name(host).into();
        entry.source = AuditSource::Observed;
        entry.verdict = AuditVerdict::Allowed;
        entry.native = Some(NativeDetail {
            host: host.into(),
            session: None,
            cwd: None,
            subject: "command".into(),
            would_hold: reason.map(str::to_string),
            agent_type: None,
            via_prism: duplicate,
        });
        entry
    }

    #[tokio::test]
    async fn rotated_history_over_5000_survives_restart_and_size_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (events, _) = crate::events::channel();
        let audit = AuditLog::new(&path, events.clone()).unwrap();
        let writer = audit.clone();
        let at = Utc::now() - chrono::Duration::minutes(1);
        tokio::task::spawn_blocking(move || {
            for index in 0..18000 {
                let mut entry =
                    native_entry(at, &format!("row-{index:05}"), "codex", Some("sudo"), false);
                entry.tool = "t".repeat(512);
                entry.native.as_mut().unwrap().subject = "s".repeat(512);
                writer.record(entry);
                if index % 128 == 127 {
                    writer.drain_pending();
                }
            }
            writer.drain_pending();
        })
        .await
        .unwrap();
        let query = AuditQuery {
            days: 30,
            limit: 17,
            ..Default::default()
        };
        let before = audit.query(query.clone()).await.unwrap();
        assert_eq!(before.total, 18000);
        assert_eq!(before.entries[0].id, "row-17999");
        assert!(before.has_more);
        assert_eq!(before.window.max_history_bytes, u64::MAX);
        assert!(!before.window.size_limited);
        assert!(!before.window.full_window_guaranteed);
        let all = audit.export(query.clone()).await.unwrap();
        assert_eq!(all.total, before.total);
        assert_eq!(all.jsonl.lines().count(), before.total);
        let last = audit
            .query(AuditQuery {
                offset: before.total - 1,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(last.entries.len(), 1);
        assert!(!last.has_more);
        let empty = audit
            .query(AuditQuery {
                offset: usize::MAX,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(empty.total, before.total);
        assert!(empty.entries.is_empty());
        assert!(!empty.has_more);
        let summary = audit
            .read(7, |snapshot| {
                Ok(crate::activity::summarize(
                    snapshot.entries.iter().map(AsRef::as_ref),
                    7,
                    snapshot.window.snapshot_at,
                ))
            })
            .await
            .unwrap();
        assert_eq!(summary.total, before.total);
        assert_eq!(summary.agents[0].id, "host:codex");
        assert_eq!(summary.agents[0].total, before.total);
        assert_eq!(audit.list(usize::MAX).len(), before.total);
        audit.close();
        drop(audit);
        let reopened = AuditLog::new(&path, events).unwrap();
        let after = reopened.query(query).await.unwrap();
        assert_eq!(after.total, before.total);
        assert_eq!(after.entries, before.entries);
        assert_eq!(
            reopened
                .export(AuditQuery {
                    days: 30,
                    ..Default::default()
                })
                .await
                .unwrap()
                .jsonl,
            all.jsonl
        );
        assert!(!archive(&path, ARCHIVES + 1).exists());
    }

    #[tokio::test]
    async fn exact_filters_exports_and_harness_ids_share_summary_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (events, _) = crate::events::channel();
        let now = Utc::now() - chrono::Duration::seconds(1);
        let yesterday = now - chrono::Duration::days(1);
        let mut mcp = entry(now, "mcp");
        mcp.agent_id = "historical-uuid".into();
        mcp.agent_name = "Claude Code 2.1".into();
        let mut remote = native_entry(now, "remote", "codex", Some("sudo"), false);
        remote.agent_id = "host:codex@workstation".into();
        let records = vec![
            native_entry(yesterday, "old", "claude-code", Some("sudo"), false),
            native_entry(now, "hit", "claude-code", Some("sudo"), false),
            native_entry(now, "routine", "claude-code", None, false),
            native_entry(now, "other-reason", "claude-code", Some("rm"), false),
            native_entry(now, "duplicate", "claude-code", Some("sudo"), true),
            native_entry(now, "codex", "codex", Some("sudo"), false),
            native_entry(
                now - chrono::Duration::days(20),
                "older-hit",
                "codex",
                Some("sudo"),
                false,
            ),
            entry(now, "unknown"),
            mcp,
            remote,
        ];
        let text = records
            .iter()
            .map(|entry| format!("{}\n", serde_json::to_string(entry).unwrap()))
            .collect::<String>();
        // Legacy UUIDs group for presentation across archive reads but remain intact in rows/exports.
        fs::write(archive(&path, 1), text).unwrap();
        let audit = AuditLog::new(&path, events).unwrap();
        let summary = audit
            .read(7, |snapshot| {
                Ok(crate::activity::summarize(
                    snapshot.entries.iter().map(AsRef::as_ref),
                    7,
                    snapshot.window.snapshot_at,
                ))
            })
            .await
            .unwrap();
        let page = audit.query(AuditQuery::default()).await.unwrap();
        assert_eq!(page.total, 8);
        assert_eq!(summary.total, page.total);
        for agent in &summary.agents {
            let query = AuditQuery {
                agent_id: Some(agent.id.clone()),
                ..Default::default()
            };
            assert_eq!(audit.query(query.clone()).await.unwrap().total, agent.total);
            assert_eq!(
                audit
                    .query(AuditQuery {
                        attention: Some(true),
                        ..query
                    })
                    .await
                    .unwrap()
                    .total,
                agent.attention
            );
        }
        assert!(page
            .entries
            .iter()
            .any(|entry| entry.id == "unknown" && entry.agent_id == "a"));
        assert!(page
            .entries
            .iter()
            .any(|entry| entry.id == "remote" && entry.agent_id == "host:codex@workstation"));
        let query: AuditQuery = serde_json::from_value(serde_json::json!({
            "agentId": "host:claude-code", "attention": true,
            "day": now.with_timezone(&Local).date_naive(), "reason": "sudo", "limit": 1,
        }))
        .unwrap();
        let filtered = audit.query(query.clone()).await.unwrap();
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.entries[0].id, "hit");
        let exported = audit
            .export(AuditQuery {
                offset: usize::MAX,
                limit: 0,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(exported.total, 1);
        let exported_entry: AuditEntry = serde_json::from_str(exported.jsonl.trim()).unwrap();
        assert_eq!(exported_entry, filtered.entries[0]);
        assert_eq!(
            audit
                .query(AuditQuery {
                    include_via_prism: true,
                    ..query
                })
                .await
                .unwrap()
                .total,
            2
        );
        assert_eq!(
            audit
                .query(AuditQuery {
                    native_only: true,
                    attention: Some(false),
                    ..Default::default()
                })
                .await
                .unwrap()
                .total,
            1
        );
        let thirty = audit
            .export(AuditQuery {
                days: 30,
                native_only: true,
                attention: Some(true),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(thirty.jsonl.contains("older-hit"));
        assert!(!thirty.jsonl.contains("duplicate"));
        assert!(!thirty.jsonl.contains("\"id\":\"mcp\""));
    }

    #[tokio::test]
    async fn retention_windows_cache_reuse_and_read_failures_are_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (events, _) = crate::events::channel();
        let audit = AuditLog::new(&path, events).unwrap();
        let now = Utc::now();
        audit.record(entry(now - chrono::Duration::days(31), "expired"));
        audit.record(entry(now - chrono::Duration::days(2), "recent"));
        audit.record(entry(now + chrono::Duration::hours(1), "future"));
        let thirty = audit
            .query(AuditQuery {
                days: u32::MAX,
                limit: usize::MAX,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(thirty.total, 1);
        assert_eq!(thirty.window.days, 30);
        assert_eq!(thirty.limit, MAX_QUERY_LIMIT);
        assert_eq!(thirty.window.archive_count, 3);
        assert_eq!(
            thirty.window.oldest_available_at,
            Some(now - chrono::Duration::days(2))
        );
        assert!(audit
            .query(AuditQuery {
                days: 0,
                ..Default::default()
            })
            .await
            .unwrap()
            .entries
            .is_empty());
        let cached = audit
            .read(7, |snapshot| Ok(snapshot.entries))
            .await
            .unwrap();
        let again = audit
            .read(7, |snapshot| Ok(snapshot.entries))
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&cached, &again),
            "unchanged ticks reuse parsed/sorted data"
        );
        audit.close();
        fs::rename(&path, dir.path().join("saved")).unwrap();
        assert!(audit.query(AuditQuery::default()).await.is_err());
        assert!(audit.export(AuditQuery::default()).await.is_err());
        fs::create_dir(&path).unwrap();
        assert!(audit.query(AuditQuery::default()).await.is_err());
        fs::remove_dir(&path).unwrap();
        fs::write(&path, "not json\n").unwrap();
        assert!(audit.query(AuditQuery::default()).await.is_err());
        fs::rename(dir.path().join("saved"), &path).unwrap();
        assert_eq!(audit.query(AuditQuery::default()).await.unwrap().total, 1);
        // Changing a file invalidates the cache; errors never replace it with an empty success.
        fs::write(archive(&path, 1), "not json\n").unwrap();
        assert!(audit.query(AuditQuery::default()).await.is_err());
        let restarted = AuditLog::new(&path, crate::events::channel().0).unwrap();
        assert!(restarted.query(AuditQuery::default()).await.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disk_work_does_not_block_the_async_runtime_and_snapshots_include_accepted_writes() {
        let dir = tempfile::tempdir().unwrap();
        let audit =
            AuditLog::new(dir.path().join("audit.jsonl"), crate::events::channel().0).unwrap();
        // Hold the disk/cache mutex on an OS thread. Both record and query must leave the sole
        // async thread available to release it; directly locking it would deadlock this test.
        let writer = audit.writer.clone();
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let held = std::thread::spawn(move || {
            let _writer = writer.lock().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        locked_rx.await.unwrap();
        audit.record(entry(Utc::now(), "accepted"));
        let reader = audit.clone();
        let read = tokio::spawn(async move { reader.query(AuditQuery::default()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        release_tx.send(()).unwrap();
        let page = read.await.unwrap().unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.entries[0].id, "accepted");
        held.join().unwrap();
    }

    #[tokio::test]
    async fn frozen_snapshot_keeps_pagination_and_exports_on_the_summary_window() {
        let dir = tempfile::tempdir().unwrap();
        let audit =
            AuditLog::new(dir.path().join("audit.jsonl"), crate::events::channel().0).unwrap();
        let at = Utc::now() - chrono::Duration::seconds(2);
        audit.record(entry(at - chrono::Duration::seconds(2), "first"));
        audit.record(entry(at - chrono::Duration::seconds(1), "second"));
        let query: AuditQuery = serde_json::from_value(serde_json::json!({
            "snapshotAt": at, "limit": 1,
        }))
        .unwrap();
        let first_page = audit.query(query.clone()).await.unwrap();
        assert_eq!(first_page.total, 2);
        assert_eq!(first_page.entries[0].id, "second");
        audit.record(entry(at + chrono::Duration::seconds(1), "later"));
        let next = audit
            .query(AuditQuery {
                offset: 1,
                ..query.clone()
            })
            .await
            .unwrap();
        assert_eq!(next.total, 2);
        assert_eq!(next.entries[0].id, "first");
        assert_eq!(next.window.snapshot_at, at);
        assert_eq!(next.window.first_day, first_page.window.first_day);
        assert!(next.window.read_at >= first_page.window.read_at);
        assert!(next.window.retention_may_remove_entries);
        let exported = audit.export(query.clone()).await.unwrap();
        assert_eq!(exported.total, 2);
        assert!(!exported.jsonl.contains("later"));
        assert_eq!(audit.query(AuditQuery::default()).await.unwrap().total, 3);
        assert!(audit
            .query(AuditQuery {
                at: Some(Utc::now() + chrono::Duration::days(1)),
                ..query
            })
            .await
            .is_err());
    }

    #[test]
    fn cleanup_expires_archive_rows_and_rebuilds_the_same_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let now = Utc::now();
        fs::write(
            archive(&path, 1),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&entry(now - chrono::Duration::days(31), "old")).unwrap(),
                serde_json::to_string(&entry(now - chrono::Duration::days(3), "kept")).unwrap(),
            ),
        )
        .unwrap();
        let audit = AuditLog::new(&path, crate::events::channel().0).unwrap();
        assert_eq!(audit.list(10).len(), 1);
        assert_eq!(audit.list(10)[0].id, "kept");
        assert!(!fs::read_to_string(archive(&path, 1))
            .unwrap()
            .contains("\"id\":\"old\""));
        audit.cleanup().unwrap();
        assert_eq!(audit.list(10)[0].id, "kept");
    }

    #[tokio::test]
    async fn crash_tail_keeps_startup_operational_preserves_bytes_and_suspends_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let archive_path = archive(&path, 1);
        let valid = format!(
            "{}\n",
            serde_json::to_string(&entry(Utc::now(), "valid")).unwrap()
        );
        let corrupt = format!("{valid}{{\"id\":\"partial");
        let expired = format!(
            "{}\n",
            serde_json::to_string(&entry(Utc::now() - chrono::Duration::days(31), "expired",))
                .unwrap()
        );
        fs::write(&path, &corrupt).unwrap();
        fs::write(&archive_path, &expired).unwrap();
        let audit = AuditLog::new(&path, crate::events::channel().0).unwrap();
        assert!(audit.query(AuditQuery::default()).await.is_err());
        assert!(audit.export(AuditQuery::default()).await.is_err());
        audit.record(entry(Utc::now(), "must-not-append"));
        let copy = audit.clone();
        tokio::task::spawn_blocking(move || copy.close())
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), corrupt);
        assert_eq!(fs::read_to_string(&archive_path).unwrap(), expired);
        assert!(audit.cleanup().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), corrupt);
        // Repair and restart re-enables history; a failed process never silently clears its error.
        fs::write(&path, valid).unwrap();
        let recovered = AuditLog::new(&path, crate::events::channel().0).unwrap();
        assert_eq!(
            recovered.query(AuditQuery::default()).await.unwrap().total,
            1
        );
        assert!(audit.query(AuditQuery::default()).await.is_err());
    }

    #[tokio::test]
    async fn presentation_mapping_never_rewrites_recorded_exported_or_reopened_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let (events, mut received) = crate::events::channel();
        let audit = AuditLog::new(&path, events.clone()).unwrap();
        let mut raw = entry(Utc::now(), "original");
        raw.agent_id = "registration-id".into();
        raw.agent_name = "Codex".into();
        audit.record(raw.clone());
        let query = AuditQuery {
            agent_id: Some("host:codex".into()),
            ..Default::default()
        };
        let page = audit.query(query.clone()).await.unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.entries[0].agent_id, raw.agent_id);
        assert_eq!(
            audit
                .query(AuditQuery {
                    agent_id: Some(raw.agent_id.clone()),
                    ..Default::default()
                })
                .await
                .unwrap()
                .total,
            1
        );
        let GatewayEvent::Audit(event) = received.recv().await.unwrap() else {
            panic!("expected audit event");
        };
        assert_eq!(event.agent_id, raw.agent_id);
        let export = audit.export(query.clone()).await.unwrap();
        let exported: AuditEntry = serde_json::from_str(export.jsonl.trim()).unwrap();
        assert_eq!(exported.agent_id, raw.agent_id);
        let on_disk: AuditEntry =
            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(on_disk.agent_id, raw.agent_id);
        audit.close();
        let reopened = AuditLog::new(&path, events).unwrap();
        assert_eq!(
            reopened.query(query).await.unwrap().entries[0].agent_id,
            raw.agent_id
        );
        let on_disk: AuditEntry =
            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(on_disk.agent_id, raw.agent_id);
        let query: AuditQuery = serde_json::from_value(serde_json::json!({
            "canonicalization_exclusions": ["registration-id"]
        }))
        .unwrap();
        assert!(query.canonicalization_exclusions.is_empty());
        assert!(serde_json::to_value(query)
            .unwrap()
            .get("canonicalization_exclusions")
            .is_none());
    }

    #[test]
    fn canonicalization_preserves_unknown_hosts_and_remote_origins() {
        let mut row = entry(Utc::now(), "id");
        row.agent_id = "uuid".into();
        row.agent_name = "Claude Code 2.1".into();
        assert_eq!(canonical_agent_id(&row), "host:claude-code");
        row.agent_name = "Codex CLI".into();
        assert_eq!(canonical_agent_id(&row), "host:codex");
        row.agent_name = "Unknown Agent".into();
        assert_eq!(canonical_agent_id(&row), "uuid");
        row.agent_id = "host:Codex@192.0.2.1".into();
        assert_eq!(canonical_agent_id(&row), "host:codex@192.0.2.1");
        row.agent_id = "host:future-host@remote".into();
        row.agent_name = "Codex".into();
        assert_eq!(canonical_agent_id(&row), "host:future-host@remote");
    }
}
