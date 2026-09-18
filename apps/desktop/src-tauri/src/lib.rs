//! Prism desktop tray app: hosts `prism-core`, tray panel, and Tauri commands.
mod harness;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use prism_core::{
    AgentConfig, AgentView, Attention, Decision, Gateway, GatewayEvent, NewRule, PanelAnchor,
    PendingCall, Posture, PrismConfig, Rule, ServerConfig, ServerView, Settings, ToolInfo,
};
use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, RunEvent, State, WebviewUrl,
    WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;
use tracing::{error, warn};

const TRAY_ID: &str = "prism-tray";
const PANEL_LABEL: &str = "panel";
/// Window size in logical pixels: a 400x600 panel plus a 16px gutter on every side so the CSS shadow can fade
/// out inside the transparent window instead of being clipped square at its edge. Mirrors tauri.conf.json.
const PANEL_SIZE: (f64, f64) = (432.0, 632.0);
/// Emitted whenever the panel is shown or hidden, so the webview can reset navigation before
/// anything is visible.
const PANEL_EVENT: &str = "prism://panel";
#[derive(Serialize, Clone)]
struct PanelEvent {
    visible: bool,
    reason: &'static str,
}
/// The panel's global shortcut unless `panel_shortcut` says otherwise.
#[allow(non_snake_case)]
fn DEFAULT_SHORTCUT() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL.union(Modifiers::ALT)), Code::KeyP)
}

struct AppState {
    gateway: Arc<Gateway>,
}

/// What the panel needs to know about a newer release. `installable` is false on Linux outside an
/// AppImage, where the updater cannot replace a package-manager install; the panel links to the
/// release instead.
#[derive(Clone, Serialize)]
struct UpdateInfo {
    version: String,
    current: String,
    notes: Option<String>,
    date: Option<String>,
    installable: bool,
}

/// Progress of an update, for the panel. Emitted on `prism://update`.
#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum UpdateEvent {
    Available(UpdateInfo),
    UpToDate,
    Downloading { downloaded: u64, total: Option<u64> },
    Installing,
    Error { message: String },
}

#[derive(Default)]
struct UpdateState {
    update: Mutex<Option<tauri_plugin_updater::Update>>,
    info: Mutex<Option<UpdateInfo>>,
    checked_at: Mutex<Option<String>>,
    busy: AtomicBool,
}

const UPDATE_EVENT: &str = "prism://update";
/// Startup delay before the first check, then the interval between checks.
const UPDATE_FIRST_CHECK: std::time::Duration = std::time::Duration::from_secs(20);
const UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

static LAST_SHOW_MS: AtomicU64 = AtomicU64::new(0);
static IGNORE_FOCUS_LOSS: AtomicBool = AtomicBool::new(false);
/// Set once the panel has actually received focus since it was shown; blur only hides after that.
static SEEN_FOCUS: AtomicBool = AtomicBool::new(false);
/// Calls resolved without a human that asked for a badge, not yet seen. Cleared when the panel opens.
static UNSEEN: AtomicU64 = AtomicU64::new(0);
/// Where the cursor was when the tray was last used. It only ever says which monitor the tray
/// is on; the panel's corner never follows the pointer.
static TRAY_HINT: Mutex<Option<PhysicalPosition<f64>>> = Mutex::new(None);
/// The tray icon's rectangle from the last tray event, on the platforms that report it (macOS and
/// Windows). Physical pixels. Linux tray events carry no usable rect.
static TRAY_RECT: Mutex<Option<(PhysicalPosition<i32>, tauri::PhysicalSize<u32>)>> =
    Mutex::new(None);
/// Linux: where our tray icon sits, in root physical pixels, on the desktops that embed it as
/// an X window of ours (XEmbed trays: Cinnamon, XFCE, MATE). It never moves, so it says which
/// monitor and edge the bar is on and, on a desktop that reserves no space for its bar, how
/// tall the bar is. Refreshed on the main thread whenever the panel is placed from there; other
/// threads use the last reading. Empty on Wayland and SNI trays, where the icon is not ours.
#[cfg(target_os = "linux")]
static TRAY_ICON: Mutex<Option<(PhysicalPosition<i32>, tauri::PhysicalSize<u32>)>> =
    Mutex::new(None);
/// The thread `run` started on: the one GDK may be used from.
#[cfg(target_os = "linux")]
static MAIN_THREAD: std::sync::OnceLock<std::thread::ThreadId> = std::sync::OnceLock::new();

#[derive(Clone, Serialize)]
struct ConnectSnippetDto {
    url: String,
    mcp_json: String,
    network_url: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn panel_window(app: &AppHandle) -> Option<tauri::WebviewWindow> {
    app.get_webview_window(PANEL_LABEL)
}

/// Place the panel. The same spot every time it opens, however it was opened: tray, shortcut,
/// or a pending call. macOS and Windows report the icon's rect through tray events, so on
/// `auto` the panel hangs off the icon there: below a top bar, above a bottom taskbar, inside
/// the work area. Everywhere else it is a corner of the tray's monitor, inside the work area:
/// the operator's `panel_anchor`, or on `auto` the corner the desktop's reserved bar points at.
/// The pointer never decides the corner; on Linux it once did, and the panel wandered.
fn position_panel(app: &AppHandle, window: &tauri::WebviewWindow) {
    #[cfg(target_os = "linux")]
    refresh_tray_icon();
    let anchor = app
        .try_state::<AppState>()
        .map(|s| s.gateway.panel_anchor())
        .unwrap_or_default();

    if anchor == PanelAnchor::Auto {
        let rect = TRAY_RECT.lock().ok().and_then(|r| *r);
        if let Some((tray_pos, tray_size)) = rect {
            match position_by_tray_rect(app, window, tray_pos, tray_size) {
                Ok(true) => return,
                Ok(false) => {}
                Err(err) => warn!(%err, "tray-anchored positioning failed"),
            }
        }
    }

    if let Err(err) = position_by_work_area(app, window, anchor) {
        warn!(%err, "could not position panel; leaving it where the window manager put it");
    }
}

/// Anchor the panel to the tray icon itself. An icon in the top half of its monitor means a top
/// bar, so the panel hangs below the work area's top edge; an icon in the bottom half means a
/// taskbar, so the panel sits on the work area's bottom edge. Horizontally it centres on the icon.
/// Every edge clamps to the work area, so a taskbar on any side is never covered.
fn position_by_tray_rect(
    app: &AppHandle,
    window: &tauri::WebviewWindow,
    tray_pos: PhysicalPosition<i32>,
    tray_size: tauri::PhysicalSize<u32>,
) -> tauri::Result<bool> {
    let centre_x = tray_pos.x as f64 + tray_size.width as f64 / 2.0;
    let centre_y = tray_pos.y as f64 + tray_size.height as f64 / 2.0;
    let monitor = match app.monitor_from_point(centre_x, centre_y)? {
        Some(m) => m,
        None => return Ok(false),
    };
    let pos = *monitor.position();
    let size = *monitor.size();
    let work = monitor.work_area();
    let win = panel_size(window, monitor.scale_factor())?;
    let margin = (8.0 * monitor.scale_factor()).round() as i32;

    let work_left = work.position.x + margin;
    let work_top = work.position.y + margin;
    let work_right = work.position.x + work.size.width as i32 - win.width as i32 - margin;
    let work_bottom = work.position.y + work.size.height as i32 - win.height as i32 - margin;

    let x = (centre_x.round() as i32 - win.width as i32 / 2)
        .clamp(work_left.min(work_right), work_right.max(work_left));
    let icon_in_top_half = centre_y < pos.y as f64 + size.height as f64 / 2.0;
    let y = if icon_in_top_half {
        // Below the icon, or the work area's top if the bar is reserved.
        (tray_pos.y + tray_size.height as i32 + margin).max(work_top)
    } else {
        // Above the icon, or the work area's bottom if the taskbar is reserved.
        (tray_pos.y - win.height as i32 - margin).min(work_bottom)
    };
    let y = y.clamp(work_top.min(work_bottom), work_bottom.max(work_top));
    window.set_position(PhysicalPosition::new(x, y))?;
    Ok(true)
}

/// The monitor the tray lives on: under the icon's rect where the platform reports one, else
/// under the last tray click however old. The tray does not move, so an old click still names
/// the right screen.
fn tray_monitor(app: &AppHandle) -> tauri::Result<Option<tauri::Monitor>> {
    #[cfg(target_os = "linux")]
    if let Some((pos, size)) = TRAY_ICON.lock().ok().and_then(|r| *r) {
        let cx = pos.x as f64 + size.width as f64 / 2.0;
        let cy = pos.y as f64 + size.height as f64 / 2.0;
        if let Some(monitor) = app.monitor_from_point(cx, cy)? {
            return Ok(Some(monitor));
        }
    }
    if let Some((pos, size)) = TRAY_RECT.lock().ok().and_then(|r| *r) {
        let cx = pos.x as f64 + size.width as f64 / 2.0;
        let cy = pos.y as f64 + size.height as f64 / 2.0;
        if let Some(monitor) = app.monitor_from_point(cx, cy)? {
            return Ok(Some(monitor));
        }
    }
    if let Some(point) = TRAY_HINT.lock().ok().and_then(|h| *h) {
        return app.monitor_from_point(point.x, point.y);
    }
    Ok(None)
}

/// The panel's size in physical pixels. A window that has never been shown can report zero, so
/// the configured size stands in until then.
fn panel_size(
    window: &tauri::WebviewWindow,
    scale: f64,
) -> tauri::Result<tauri::PhysicalSize<u32>> {
    let size = window.outer_size()?;
    if size.width > 0 && size.height > 0 {
        return Ok(size);
    }
    Ok(tauri::LogicalSize::new(PANEL_SIZE.0, PANEL_SIZE.1).to_physical(scale))
}

/// A fixed corner of the tray's monitor, inside the work area. On `auto` the corner comes from
/// what the desktop has reserved: above a bottom bar, otherwise top right, and left only for a
/// dock-style bar down the left edge. The operator's `panel_anchor` names a corner outright.
fn position_by_work_area(
    app: &AppHandle,
    window: &tauri::WebviewWindow,
    anchor: PanelAnchor,
) -> tauri::Result<()> {
    let monitor = match tray_monitor(app)? {
        Some(m) => m,
        None => match window.primary_monitor()? {
            Some(m) => m,
            None => match window.current_monitor()? {
                Some(m) => m,
                None => return Ok(()),
            },
        },
    };
    let screen_pos = *monitor.position();
    let screen = *monitor.size();
    let work = monitor.work_area();
    let win = panel_size(window, monitor.scale_factor())?;
    let margin = (8.0 * monitor.scale_factor()).round() as i32;

    let work_left = work.position.x;
    let work_right = work_left + work.size.width as i32;

    // Struts: how much of each screen edge a desktop panel has reserved.
    let strut_top = work.position.y - screen_pos.y;
    let strut_bottom =
        (screen_pos.y + screen.height as i32) - (work.position.y + work.size.height as i32);
    let strut_left = work_left - screen_pos.x;
    let strut_right = (screen_pos.x + screen.width as i32) - work_right;
    // A desktop that reserves nothing for its bar still has one where our tray icon sits.
    let nothing_reserved =
        strut_top == 0 && strut_bottom == 0 && strut_left == 0 && strut_right == 0;
    let (strut_top, strut_bottom) = match unreserved_bar(&monitor).filter(|_| nothing_reserved) {
        Some(bar) => bar,
        None => (strut_top, strut_bottom),
    };
    let work_top = screen_pos.y + strut_top;
    let work_bottom = screen_pos.y + screen.height as i32 - strut_bottom;

    let (at_bottom, at_left) = match anchor {
        PanelAnchor::TopRight => (false, false),
        PanelAnchor::TopLeft => (false, true),
        PanelAnchor::BottomRight => (true, false),
        PanelAnchor::BottomLeft => (true, true),
        PanelAnchor::Auto => {
            // A vertical panel on the left (dock-style) is the only case that pulls us left;
            // otherwise trays live at the right end of a top or bottom bar.
            let vertical_left = strut_left > 0
                && strut_left >= strut_right
                && strut_left > strut_top.max(strut_bottom);
            (strut_bottom > strut_top, vertical_left)
        }
    };

    let x = if at_left {
        work_left + margin
    } else {
        work_right - win.width as i32 - margin
    };
    let y = if at_bottom {
        work_bottom - win.height as i32 - margin
    } else {
        work_top + margin
    };
    window.set_position(PhysicalPosition::new(x, y))
}

/// Linux: a bar the desktop reserved no space for, read from where our tray icon sits on this
/// monitor. The icon is centred in its bar, so the bar is the icon plus its inset from the
/// screen edge on both sides: (top, bottom) thickness in physical pixels.
#[cfg(target_os = "linux")]
fn unreserved_bar(monitor: &tauri::Monitor) -> Option<(i32, i32)> {
    let (pos, size) = TRAY_ICON.lock().ok().and_then(|r| *r)?;
    let screen_pos = *monitor.position();
    let screen = *monitor.size();
    let cx = pos.x + size.width as i32 / 2;
    let cy = pos.y + size.height as i32 / 2;
    let on_monitor = cx >= screen_pos.x
        && cx < screen_pos.x + screen.width as i32
        && cy >= screen_pos.y
        && cy < screen_pos.y + screen.height as i32;
    if !on_monitor {
        return None;
    }
    let bottom_edge = screen_pos.y + screen.height as i32;
    let top_inset = pos.y - screen_pos.y;
    let bottom_inset = bottom_edge - (pos.y + size.height as i32);
    let thickness = |inset: i32| inset * 2 + size.height as i32;
    let bar = if cy < screen_pos.y + screen.height as i32 / 2 {
        (thickness(top_inset), 0)
    } else {
        (0, thickness(bottom_inset))
    };
    // An icon far from any edge is not in a bar we understand.
    (bar.0.max(bar.1) <= screen.height as i32 / 4).then_some(bar)
}

#[cfg(not(target_os = "linux"))]
fn unreserved_bar(_monitor: &tauri::Monitor) -> Option<(i32, i32)> {
    None
}

/// Linux: read where our tray icon sits from GDK, which knows this process's windows and their
/// root positions. Main thread only; elsewhere the last reading stands. On Wayland the icon is
/// the compositor's, so there is nothing to read.
#[cfg(target_os = "linux")]
fn refresh_tray_icon() {
    let on_main_thread = MAIN_THREAD.get() == Some(&std::thread::current().id());
    if std::env::var_os("WAYLAND_DISPLAY").is_some() || !on_main_thread {
        return;
    }
    let Some(screen) = gdk::Screen::default() else {
        return;
    };
    let found = screen
        .toplevel_windows()
        .into_iter()
        .filter(|w| {
            w.is_viewable() && (1..=64).contains(&w.width()) && (1..=64).contains(&w.height())
        })
        .map(|w| {
            let scale = w.scale_factor().max(1);
            let (_, x, y) = w.origin();
            (
                PhysicalPosition::new(x * scale, y * scale),
                tauri::PhysicalSize::new((w.width() * scale) as u32, (w.height() * scale) as u32),
            )
        })
        // Until the tray has embedded it, the icon reports the screen origin: not a reading.
        .find(|(pos, _)| pos.x != 0 || pos.y != 0);
    let Some(found) = found else {
        return;
    };
    if let Ok(mut slot) = TRAY_ICON.lock() {
        if *slot != Some(found) {
            debug!(
                x = found.0.x,
                y = found.0.y,
                w = found.1.width,
                h = found.1.height,
                "tray icon located"
            );
            *slot = Some(found);
        }
    }
}

/// The tray was just used: the cursor is on it, so this is the tray's monitor. Kept for this
/// run and, since the tray does not move, for the next one.
fn remember_tray_hint(app: &AppHandle) {
    if let Some(pos) = note_cursor_hint(app) {
        if let Some(path) = tray_hint_path(app) {
            let _ = std::fs::write(path, format!("{} {}\n", pos.x, pos.y));
        }
    }
}

/// Take the cursor's monitor as the tray's without claiming the tray is there.
fn note_cursor_hint(app: &AppHandle) -> Option<PhysicalPosition<f64>> {
    let pos = app.cursor_position().ok()?;
    if let Ok(mut hint) = TRAY_HINT.lock() {
        *hint = Some(pos);
    }
    Some(pos)
}

/// Where the last tray click was recorded between runs. Only a point, and only so the panel
/// knows which monitor the tray is on before it has been clicked in this run.
fn tray_hint_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok().map(|d| d.join("tray-hint"))
}

/// Load the previous run's tray click: the tray's monitor before anything has been clicked.
fn recall_tray_hint(app: &AppHandle) {
    let Some(text) = tray_hint_path(app).and_then(|p| std::fs::read_to_string(p).ok()) else {
        return;
    };
    let mut parts = text
        .split_whitespace()
        .filter_map(|n| n.parse::<f64>().ok());
    if let (Some(x), Some(y)) = (parts.next(), parts.next()) {
        if let Ok(mut hint) = TRAY_HINT.lock() {
            if hint.is_none() {
                *hint = Some(PhysicalPosition::new(x, y));
            }
        }
    }
}

/// Keep the icon's rectangle from a tray event in physical pixels. The rect arrives logical on
/// macOS and physical on Windows; the monitor under the cursor supplies the scale either way.
fn remember_tray_rect(app: &AppHandle, rect: &tauri::Rect) {
    let scale = app
        .cursor_position()
        .ok()
        .and_then(|p| app.monitor_from_point(p.x, p.y).ok().flatten())
        .map(|m| m.scale_factor())
        .unwrap_or(1.0);
    let pos = rect.position.to_physical::<i32>(scale);
    let size = rect.size.to_physical::<u32>(scale);
    if size.width == 0 && size.height == 0 {
        return;
    }
    if let Ok(mut slot) = TRAY_RECT.lock() {
        *slot = Some((pos, size));
    }
}

/// Development only: the panel stays on screen across focus changes so edits can be watched live.
/// Set through the environment at launch; release builds never read it from anywhere else.
fn panel_pinned() -> bool {
    std::env::var_os("PRISM_PIN_PANEL").is_some()
}

fn show_panel(app: &AppHandle, reason: &'static str) {
    // Attention can arrive while the operator is reading or typing in the panel. In that case
    // the gateway event updates the waiting pill; remapping and focusing the window would steal
    // focus and emit a false reopening lifecycle.
    if panel_window(app)
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false)
    {
        if UNSEEN.swap(0, Ordering::SeqCst) > 0 {
            if let Some(state) = app.try_state::<AppState>() {
                let gateway = state.gateway.clone();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    settle_tray_icon(&app, &gateway).await;
                });
            }
        }
        return;
    }
    // Opening the panel is how the operator sees badged calls, so the badge clears here.
    if UNSEEN.swap(0, Ordering::SeqCst) > 0 {
        if let Some(state) = app.try_state::<AppState>() {
            let gateway = state.gateway.clone();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                settle_tray_icon(&app, &gateway).await;
            });
        }
    }
    if let Some(window) = panel_window(app) {
        IGNORE_FOCUS_LOSS.store(true, Ordering::SeqCst);
        SEEN_FOCUS.store(false, Ordering::SeqCst);
        LAST_SHOW_MS.store(now_ms(), Ordering::SeqCst);
        position_panel(app, &window);
        let _ = app.emit(
            PANEL_EVENT,
            PanelEvent {
                visible: true,
                reason,
            },
        );
        let _ = window.show();
        let _ = window.set_focus();
        // Some window managers place a window themselves when it is mapped and ignore the
        // position set while it was hidden, so it is set again now and once more after the map
        // has settled.
        position_panel(app, &window);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            // On the main thread, so the tray icon can be re-read where GDK allows it.
            let placed = app.clone();
            let _ = app.run_on_main_thread(move || {
                if let Some(window) = panel_window(&placed) {
                    position_panel(&placed, &window);
                }
            });
            tokio::time::sleep(std::time::Duration::from_millis(170)).await;
            IGNORE_FOCUS_LOSS.store(false, Ordering::SeqCst);
        });
    }
}

/// The single hide path: every hide site routes through here so the webview always hears
/// `prism://panel` before the window actually disappears.
fn hide_panel_window(app: &AppHandle, reason: &'static str) {
    if let Some(window) = panel_window(app) {
        if matches!(window.is_visible(), Ok(false)) {
            return;
        }
        let _ = app.emit(
            PANEL_EVENT,
            PanelEvent {
                visible: false,
                reason,
            },
        );
        let _ = window.hide();
    }
}

fn toggle_panel(app: &AppHandle) {
    if let Some(window) = panel_window(app) {
        match window.is_visible() {
            Ok(true) => {
                hide_panel_window(app, "toggle");
            }
            _ => show_panel(app, "toggle"),
        }
    }
}

/// Pale glyph for dark bars. macOS ignores the colour (template), GNOME and KDE bars are dark,
/// and Windows gets the ink variant when its taskbar is light.
fn idle_icon(app: &AppHandle) -> Result<Image<'static>, tauri::Error> {
    #[cfg(target_os = "windows")]
    {
        let light = app
            .get_webview_window("panel")
            .and_then(|w| w.theme().ok())
            .map(|t| t == tauri::Theme::Light)
            .unwrap_or(false);
        if light {
            return Image::from_bytes(include_bytes!("../icons/tray-idle-ink.png"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = app;
    Image::from_bytes(include_bytes!("../icons/tray-idle.png"))
}

fn pending_icon() -> Result<Image<'static>, tauri::Error> {
    Image::from_bytes(include_bytes!("../icons/tray-pending.png"))
}

fn set_tray_icon(app: &AppHandle, pending: bool) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let icon = if pending {
            pending_icon()
        } else {
            idle_icon(app)
        };
        if let Ok(icon) = icon {
            // Idle is a template on macOS so the menu bar tints it; pending keeps its amber.
            let _ = tray.set_icon_with_as_template(Some(icon), !pending);
        }
    }
}

/// The panel shows this verbatim. An invalid argument is already a sentence for the operator;
/// the other kinds keep their prefix so a backend or gateway failure reads as one.
fn map_err(err: prism_core::Error) -> String {
    match err {
        prism_core::Error::Invalid(message) => message,
        other => other.to_string(),
    }
}

#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<prism_core::GatewayStatus, String> {
    Ok(state.gateway.status().await)
}

#[tauri::command]
async fn list_servers(state: State<'_, AppState>) -> Result<Vec<ServerView>, String> {
    Ok(state.gateway.servers().await)
}

#[derive(serde::Deserialize)]
struct AddServerArgs {
    name: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
    /// Remote server endpoint. When set, `command` is ignored.
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    auth: prism_core::HttpAuth,
    #[serde(default)]
    headers: std::collections::BTreeMap<String, String>,
}

#[tauri::command]
async fn add_server(state: State<'_, AppState>, args: AddServerArgs) -> Result<ServerView, String> {
    let server = ServerConfig {
        id: String::new(),
        name: args.name,
        command: args.command,
        args: args.args,
        env: args.env,
        enabled: true,
        credential_ref: None,
        url: args.url,
        auth: args.auth,
        headers: args.headers,
        oauth_ref: None,
        hidden_tools: Default::default(),
    };
    let added = state.gateway.add_server(server).await.map_err(map_err)?;
    state
        .gateway
        .servers()
        .await
        .into_iter()
        .find(|server| server.id == added.id)
        .ok_or_else(|| "server is no longer configured".to_string())
}

#[tauri::command]
async fn remove_server(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    state
        .gateway
        .remove_server(&server_id)
        .await
        .map_err(map_err)
}

/// Start a browser sign-in for an OAuth server and open it. Returns the URL for the panel.
#[tauri::command]
async fn sign_in_server(
    app: AppHandle,
    state: State<'_, AppState>,
    server_id: String,
) -> Result<String, String> {
    use tauri_plugin_opener::OpenerExt;
    let url = state
        .gateway
        .sign_in_server(&server_id)
        .await
        .map_err(map_err)?;
    if let Err(err) = app.opener().open_url(&url, None::<&str>) {
        warn!(%err, "could not open the browser for a server sign-in");
    }
    Ok(url)
}

#[tauri::command]
async fn sign_out_server(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    state
        .gateway
        .sign_out_server(&server_id)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn restart_server(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    state
        .gateway
        .restart_server(&server_id)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn list_agents(state: State<'_, AppState>) -> Result<Vec<AgentView>, String> {
    Ok(state.gateway.agents().await)
}

#[tauri::command]
async fn create_manual_agent(
    state: State<'_, AppState>,
    name: String,
) -> Result<prism_core::ManualToken, String> {
    state
        .gateway
        .create_manual_agent(&name)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn replace_manual_token(
    state: State<'_, AppState>,
    agent_id: String,
) -> Result<prism_core::ManualToken, String> {
    state
        .gateway
        .replace_manual_token(&agent_id)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn decide_agent(
    state: State<'_, AppState>,
    agent_id: String,
    approve: bool,
) -> Result<(), String> {
    state
        .gateway
        .decide_agent(&agent_id, approve)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn remove_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    state.gateway.remove_agent(&agent_id).await.map_err(map_err)
}

#[tauri::command]
async fn list_signins(
    state: State<'_, AppState>,
) -> Result<Vec<prism_core::PendingSignIn>, String> {
    Ok(state.gateway.pending_signins())
}

#[tauri::command]
async fn decide_signin(
    state: State<'_, AppState>,
    id: String,
    approve: bool,
) -> Result<(), String> {
    state.gateway.decide_signin(&id, approve).map_err(map_err)
}

#[tauri::command]
async fn revoke_agent_tokens(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    state
        .gateway
        .revoke_agent_tokens(&agent_id)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn forget_client(
    state: State<'_, AppState>,
    agent_id: String,
    client_id: String,
) -> Result<(), String> {
    state
        .gateway
        .forget_client(&agent_id, &client_id)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn list_pending(state: State<'_, AppState>) -> Result<Vec<PendingCall>, String> {
    Ok(state.gateway.pending().await)
}

#[tauri::command]
async fn decide(state: State<'_, AppState>, id: String, decision: Decision) -> Result<(), String> {
    state.gateway.decide(&id, decision).await.map_err(map_err)
}

#[tauri::command]
async fn list_rules(state: State<'_, AppState>) -> Result<Vec<Rule>, String> {
    Ok(state.gateway.rules().await)
}

#[tauri::command]
async fn delete_rule(state: State<'_, AppState>, rule_id: String) -> Result<(), String> {
    state.gateway.delete_rule(&rule_id).await.map_err(map_err)
}

#[tauri::command]
async fn add_rule(state: State<'_, AppState>, rule: NewRule) -> Result<Rule, String> {
    state.gateway.add_rule(rule).await.map_err(map_err)
}

#[tauri::command]
async fn set_agent_policy(
    state: State<'_, AppState>,
    agent_id: String,
    posture: Option<Posture>,
    attention: Option<Attention>,
) -> Result<AgentConfig, String> {
    state
        .gateway
        .set_agent_policy(&agent_id, posture, attention)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    Ok(state.gateway.settings().await)
}

#[tauri::command]
async fn set_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    state.gateway.set_settings(settings).await.map_err(map_err)
}

/// Try the configured port again after a clash.
#[tauri::command]
async fn retry_listener(state: State<'_, AppState>) -> Result<(), String> {
    state.gateway.retry_listener().await.map_err(map_err)
}

/// A free port near the configured one. Offered, never chosen: agents dial the configured port.
#[tauri::command]
async fn suggest_port(state: State<'_, AppState>) -> Result<Option<u16>, String> {
    Ok(state.gateway.suggest_port().await)
}

#[tauri::command]
async fn set_listen_port(state: State<'_, AppState>, port: u16) -> Result<(), String> {
    state.gateway.set_listen_port(port).await.map_err(map_err)
}

/// Loopback only, or every interface so agents on other machines can connect.
#[tauri::command]
async fn set_listen_address(
    state: State<'_, AppState>,
    address: prism_core::ListenAddress,
) -> Result<(), String> {
    state
        .gateway
        .set_listen_address(address)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn list_server_tools(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<Vec<ToolInfo>, String> {
    Ok(state.gateway.server_tools(&server_id).await)
}

#[tauri::command]
async fn set_tool_exposed(
    state: State<'_, AppState>,
    server_id: String,
    tool: String,
    exposed: bool,
) -> Result<(), String> {
    state
        .gateway
        .set_tool_exposed(&server_id, &tool, exposed)
        .await
        .map_err(map_err)
}

#[tauri::command]
async fn list_audit(
    state: State<'_, AppState>,
    limit: Option<usize>,
    agent_id: Option<String>,
    attention: Option<bool>,
    day: Option<String>,
    reason: Option<String>,
) -> Result<Vec<prism_core::AuditEntry>, String> {
    let query = prism_core::AuditQuery {
        limit: limit.unwrap_or(60),
        agent_id,
        attention,
        reason,
        day: day
            .map(|d| d.parse())
            .transpose()
            .map_err(|_| "Invalid date")?,
        ..Default::default()
    };
    Ok(state
        .gateway
        .audit_query(query)
        .await
        .map_err(map_err)?
        .entries)
}

#[tauri::command]
async fn list_audit_page(
    state: State<'_, AppState>,
    query: prism_core::AuditQuery,
) -> Result<prism_core::AuditPage, String> {
    state.gateway.audit_query(query).await.map_err(map_err)
}

#[tauri::command]
async fn get_activity(
    state: State<'_, AppState>,
    days: Option<u32>,
) -> Result<prism_core::activity::ActivitySummary, String> {
    state
        .gateway
        .activity(days.unwrap_or(7))
        .await
        .map_err(map_err)
}

#[tauri::command]
fn hide_panel(app: AppHandle) -> Result<(), String> {
    hide_panel_window(&app, "hide");
    Ok(())
}

#[tauri::command]
async fn get_connect_snippet(state: State<'_, AppState>) -> Result<ConnectSnippetDto, String> {
    let snippet = state.gateway.connect_snippet().map_err(map_err)?;
    Ok(ConnectSnippetDto {
        url: snippet.url,
        mcp_json: snippet.mcp_json,
        network_url: snippet.network_url,
    })
}

// ----- native actions (observe) ---------------------------------------------------------

/// Core status plus what only the desktop knows per host: where its hook file lives and
/// whether the current hook URL is in it.
#[derive(Serialize)]
struct NativeStatusDto {
    #[serde(flatten)]
    status: prism_core::NativeStatus,
    setup: Vec<harness::Setup>,
}

#[derive(Serialize)]
struct HookInstallResult {
    path: String,
    backup: Option<String>,
}

fn home_path() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| "home directory not found".to_string())
}

#[tauri::command]
async fn get_native_status(state: State<'_, AppState>) -> Result<NativeStatusDto, String> {
    let status = state.gateway.native_status().await.map_err(map_err)?;
    let url = state.gateway.connect_snippet().map_err(map_err)?.url;
    let hosts = status.hosts.clone();
    let setup = tauri::async_runtime::spawn_blocking(move || {
        hosts
            .iter()
            .map(|host| {
                let paths = match harness::Paths::for_host(&host.host) {
                    Ok(paths) => paths,
                    Err(problem) => {
                        return Ok(harness::Setup {
                            host: host.host.clone(),
                            settings_path: String::new(),
                            mcp_path: String::new(),
                            mcp_configured: false,
                            hook_installed: false,
                            setup_present: false,
                            hooks_disabled: false,
                            events_received: false,
                            problem: Some(problem),
                        })
                    }
                };
                Ok(harness::inspect(
                    &paths,
                    &host.host,
                    &url,
                    &host.hook_url,
                    host.last_event_at,
                ))
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .await
    .map_err(|_| "Could not inspect client settings")??;
    Ok(NativeStatusDto { status, setup })
}

async fn configure_harness(
    state: &AppState,
    host: String,
    remove: bool,
    hooks_only: bool,
) -> Result<harness::Changes, String> {
    let url = state.gateway.connect_snippet().map_err(map_err)?.url;
    let hook_url = state.gateway.hook_url(&host);
    let name = host.clone();
    let changes = tauri::async_runtime::spawn_blocking(move || {
        let paths = harness::Paths::for_host(&host)?;
        harness::configure(&paths, &host, &url, &hook_url, remove, hooks_only)
    })
    .await
    .map_err(|_| "Could not update client settings")??;
    if !remove {
        // Setup succeeded on disk; list the harness now rather than after its first contact.
        state
            .gateway
            .ensure_host_agent(&name)
            .await
            .map_err(map_err)?;
    }
    Ok(changes)
}

#[tauri::command]
async fn setup_harness(
    state: State<'_, AppState>,
    host: String,
) -> Result<harness::Changes, String> {
    configure_harness(&state, host, false, false).await
}

#[tauri::command]
async fn remove_harness_setup(
    state: State<'_, AppState>,
    host: String,
) -> Result<harness::Changes, String> {
    configure_harness(&state, host, true, false).await
}

#[tauri::command]
async fn set_observe_native(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    state.gateway.set_observe_native(on).await.map_err(map_err)
}

#[tauri::command]
async fn rotate_hook_token(state: State<'_, AppState>) -> Result<(), String> {
    state.gateway.rotate_hook_token().await.map_err(map_err)
}

/// The exact `hooks` entry for the host's file, for the copy button.
#[tauri::command]
async fn get_host_hook_snippet(state: State<'_, AppState>, host: String) -> Result<String, String> {
    let url = state.gateway.hook_url(&host);
    harness::snippet(&host, &url)
}

/// Hook-only repair for installations created before the combined harness setup flow.
#[tauri::command]
async fn install_host_hook(
    state: State<'_, AppState>,
    host: String,
) -> Result<HookInstallResult, String> {
    let path = harness::Paths::for_host(&host)?.hooks.display().to_string();
    let changes = configure_harness(&state, host, false, true).await?;
    Ok(HookInstallResult {
        path,
        backup: changes.backups.into_iter().next(),
    })
}

#[derive(Serialize)]
struct ExportReportDto {
    path: String,
    metadata_path: String,
    total: usize,
}

/// Where every export lands. Downloads, or the home directory when the platform has none.
fn export_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .download_dir()
        .or_else(|_| app.path().home_dir())
        .map_err(|e| e.to_string())
}

/// Write an export and its exact retention window beside the JSONL, under `<stem_prefix><stamp>`.
async fn write_audit_export(
    app: &AppHandle,
    report: prism_core::AuditExport,
    stem_prefix: &str,
) -> Result<ExportReportDto, String> {
    let dir = export_dir(app)?;
    let stem = format!(
        "{stem_prefix}{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S-%f")
    );
    tauri::async_runtime::spawn_blocking(move || {
        let path = dir.join(format!("{stem}.jsonl"));
        let metadata_path = dir.join(format!("{stem}.metadata.json"));
        let metadata = serde_json::to_vec_pretty(
            &serde_json::json!({"total":report.total,"window":report.window}),
        )
        .map_err(|e| e.to_string())?;
        prism_core::write_client_config(&metadata_path, &metadata)
            .map_err(|_| "Could not save report metadata")?;
        prism_core::write_client_config(&path, report.jsonl.as_bytes())
            .map_err(|_| "Could not save audit report")?;
        Ok(ExportReportDto {
            path: path.display().to_string(),
            metadata_path: metadata_path.display().to_string(),
            total: report.total,
        })
    })
    .await
    .map_err(|_| "Could not export report")?
}

/// Export retained matches and their exact retention window beside the JSONL.
#[tauri::command]
async fn export_native_report(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ExportReportDto, String> {
    let report = state
        .gateway
        .audit_export(prism_core::AuditQuery {
            days: 30,
            native_only: true,
            attention: Some(true),
            ..Default::default()
        })
        .await
        .map_err(map_err)?;
    write_audit_export(&app, report, "prism-native-").await
}

/// Export exactly the rows a filtered Actions view holds. Nothing beyond what `audit.jsonl` keeps.
#[tauri::command]
async fn export_audit(
    app: AppHandle,
    state: State<'_, AppState>,
    query: prism_core::AuditQuery,
) -> Result<ExportReportDto, String> {
    let report = state.gateway.audit_export(query).await.map_err(map_err)?;
    write_audit_export(&app, report, "prism-actions-").await
}

/// Open an export Prism wrote: a `.jsonl` that resolves inside the export directory, nothing else.
/// The path comes back through the webview, so it is re-checked here rather than trusted.
#[tauri::command]
fn open_export(app: AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let dir = export_dir(&app)?
        .canonicalize()
        .map_err(|_| "Could not find the downloads folder".to_string())?;
    let file = std::path::Path::new(&path)
        .canonicalize()
        .map_err(|_| "That export is no longer there".to_string())?;
    if !file.starts_with(&dir) || file.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
        return Err("Not an export Prism wrote".to_string());
    }
    app.opener()
        .open_path(file.display().to_string(), None::<&str>)
        .map_err(|_| "Could not open the export".to_string())
}

/// Open the retained log itself, the file every export is drawn from.
#[tauri::command]
fn open_audit_log(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let (_, audit_path) = config_paths(&app)?;
    if !audit_path.exists() {
        return Err("No log yet".to_string());
    }
    app.opener()
        .open_path(audit_path.display().to_string(), None::<&str>)
        .map_err(|_| "Could not open the log".to_string())
}

/// Open the raw MCP JSON-RPC traffic log.
#[tauri::command]
fn open_mcp_log(app: AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let (_, audit_path) = config_paths(&app)?;
    let mcp_path = audit_path.with_file_name("mcp.jsonl");
    if !mcp_path.exists() {
        return Err("No MCP traffic log yet".to_string());
    }
    app.opener()
        .open_path(mcp_path.display().to_string(), None::<&str>)
        .map_err(|_| "Could not open the MCP traffic log".to_string())
}

fn config_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let config_dir = app.path().app_config_dir().map_err(|err| err.to_string())?;
    let data_dir = app.path().app_data_dir().map_err(|err| err.to_string())?;
    std::fs::create_dir_all(&config_dir).map_err(|err| err.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|err| err.to_string())?;
    Ok((config_dir.join("prism.json"), data_dir.join("audit.jsonl")))
}

fn ensure_auto_open_default(path: &PathBuf) {
    if !path.exists() {
        let config = PrismConfig::default();
        if let Err(err) = config.save(path) {
            warn!(%err, "failed to write default prism.json");
        }
    }
}

fn forward_events(app: AppHandle, gateway: Arc<Gateway>) {
    tauri::async_runtime::spawn(async move {
        let mut rx = gateway.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    handle_gateway_event(&app, &gateway, &event).await;
                    if let Err(err) = app.emit("prism://event", &event) {
                        warn!(%err, "failed to emit prism://event");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!(n, "gateway event subscriber lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn handle_gateway_event(app: &AppHandle, gateway: &Gateway, event: &GatewayEvent) {
    match event {
        GatewayEvent::PendingCall(call) => {
            let body = format!(
                "{} wants to call {}/{}",
                call.agent_name, call.server_name, call.tool
            );
            attention(app, gateway, &body).await;
        }
        GatewayEvent::AgentRequested(agent) => {
            let body = format!("{} wants to connect", agent.name);
            attention(app, gateway, &body).await;
        }
        GatewayEvent::SignInRequested(signin) => {
            let body = format!("{} wants to sign in again", signin.agent_name);
            attention(app, gateway, &body).await;
        }
        // A call resolved without a human. The rule or agent says how loudly to surface it.
        GatewayEvent::Audit(entry) if entry.attention != Attention::Silent => {
            UNSEEN.fetch_add(1, Ordering::SeqCst);
            set_tray_icon(app, true);
            if entry.attention >= Attention::Notify {
                let outcome = match entry.verdict {
                    prism_core::AuditVerdict::Allowed => "allowed",
                    prism_core::AuditVerdict::Denied => "denied",
                    prism_core::AuditVerdict::Timeout => "timed out",
                    prism_core::AuditVerdict::Error => "failed",
                };
                let body = format!("{} · {} {}", entry.agent_name, entry.tool, outcome);
                if let Err(err) = app
                    .notification()
                    .builder()
                    .title("Prism")
                    .body(body)
                    .show()
                {
                    warn!(%err, "notification failed");
                }
            }
            if entry.attention == Attention::Open {
                show_panel(app, "app");
            }
        }
        GatewayEvent::CallDecided { .. }
        | GatewayEvent::CallCancelled { .. }
        | GatewayEvent::Audit(_)
        | GatewayEvent::AgentDecided { .. }
        | GatewayEvent::SignInDecided { .. } => {
            settle_tray_icon(app, gateway).await;
        }
        _ => {}
    }
}

/// Idle icon once nothing is waiting and nothing badged is unseen.
async fn settle_tray_icon(app: &AppHandle, gateway: &Gateway) {
    let status = gateway.status().await;
    if status.pending_count == 0
        && status.pending_agents == 0
        && status.pending_signins == 0
        && UNSEEN.load(Ordering::SeqCst) == 0
    {
        set_tray_icon(app, false);
    }
}

/// Something needs a human: flip the tray icon, notify, and open the panel if configured.
async fn attention(app: &AppHandle, gateway: &Gateway, body: &str) {
    set_tray_icon(app, true);
    if let Err(err) = app
        .notification()
        .builder()
        .title("Prism")
        .body(body)
        .show()
    {
        warn!(%err, "notification failed");
    }
    if gateway.status().await.auto_open_on_pending {
        show_panel(app, "attention");
    }
}

/// Whether the updater can replace this install by itself. The bundler stamps the bundle type
/// into the binary; a bare `cargo build` or an unknown package manager gets the release page instead.
/// Deb and rpm installs go through `pkexec`, so the user sees a privilege prompt on those.
fn update_installable() -> bool {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    if cfg!(target_os = "linux") {
        matches!(
            bundle_type(),
            Some(BundleType::AppImage | BundleType::Deb | BundleType::Rpm)
        )
    } else {
        true
    }
}

/// Ask the release endpoint whether something newer exists. Remembers the answer for the panel and
/// tells it through the update event. Errors are reported, never fatal: an offline check is normal.
async fn check_for_update(app: &AppHandle, announce: bool) -> Result<Option<UpdateInfo>, String> {
    let state = app.state::<UpdateState>();
    let updater = app.updater().map_err(|e| e.to_string())?;
    let result = updater.check().await;
    if let Ok(mut at) = state.checked_at.lock() {
        *at = Some(chrono::Utc::now().to_rfc3339());
    }
    match result {
        Ok(Some(update)) => {
            let info = UpdateInfo {
                version: update.version.clone(),
                current: update.current_version.clone(),
                notes: update.body.clone(),
                date: update.date.map(|d| d.to_string()),
                installable: update_installable(),
            };
            if let Ok(mut slot) = state.update.lock() {
                *slot = Some(update);
            }
            if let Ok(mut slot) = state.info.lock() {
                *slot = Some(info.clone());
            }
            if announce {
                let _ = app.emit(UPDATE_EVENT, UpdateEvent::Available(info.clone()));
            }
            Ok(Some(info))
        }
        Ok(None) => {
            if let Ok(mut slot) = state.update.lock() {
                *slot = None;
            }
            if let Ok(mut slot) = state.info.lock() {
                *slot = None;
            }
            if announce {
                let _ = app.emit(UPDATE_EVENT, UpdateEvent::UpToDate);
            }
            Ok(None)
        }
        Err(err) => {
            warn!(%err, "update check failed");
            if announce {
                let _ = app.emit(
                    UPDATE_EVENT,
                    UpdateEvent::Error {
                        message: err.to_string(),
                    },
                );
            }
            Err(err.to_string())
        }
    }
}

fn start_update_checks(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(UPDATE_FIRST_CHECK).await;
        loop {
            let _ = check_for_update(&app, true).await;
            tokio::time::sleep(UPDATE_INTERVAL).await;
        }
    });
}

#[derive(Clone, Serialize)]
struct UpdateStatusDto {
    current: String,
    available: Option<UpdateInfo>,
    checked_at: Option<String>,
    installable: bool,
}

#[tauri::command]
fn get_update_status(app: AppHandle, state: State<'_, UpdateState>) -> UpdateStatusDto {
    UpdateStatusDto {
        current: app.package_info().version.to_string(),
        available: state.info.lock().ok().and_then(|i| i.clone()),
        checked_at: state.checked_at.lock().ok().and_then(|c| c.clone()),
        installable: update_installable(),
    }
}

#[tauri::command]
async fn check_update(app: AppHandle) -> Result<Option<UpdateInfo>, String> {
    check_for_update(&app, false).await
}

/// Download, install and relaunch. The panel watches `prism://update` for progress. On Windows the
/// installer takes over and the process exits; elsewhere Prism restarts itself.
#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let state = app.state::<UpdateState>();
    if state.busy.swap(true, Ordering::SeqCst) {
        return Err("an update is already installing".into());
    }
    let update = state.update.lock().ok().and_then(|u| u.clone());
    let Some(update) = update else {
        state.busy.store(false, Ordering::SeqCst);
        return Err("no update has been found yet".into());
    };
    if !update_installable() {
        state.busy.store(false, Ordering::SeqCst);
        return Err("this install cannot update itself; download the new release instead".into());
    }
    let progress_app = app.clone();
    let mut downloaded: u64 = 0;
    let result = update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ =
                    progress_app.emit(UPDATE_EVENT, UpdateEvent::Downloading { downloaded, total });
            },
            || {},
        )
        .await;
    match result {
        Ok(()) => {
            let _ = app.emit(UPDATE_EVENT, UpdateEvent::Installing);
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            app.restart();
        }
        Err(err) => {
            state.busy.store(false, Ordering::SeqCst);
            let message = err.to_string();
            let _ = app.emit(
                UPDATE_EVENT,
                UpdateEvent::Error {
                    message: message.clone(),
                },
            );
            Err(message)
        }
    }
}

fn build_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let open = MenuItem::with_id(app, "open", "Open Prism", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let icon = idle_icon(app)?;

    #[allow(unused_mut)]
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Prism")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                remember_tray_hint(app);
                show_panel(app, "tray");
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            match &event {
                TrayIconEvent::Click { rect, .. }
                | TrayIconEvent::Enter { rect, .. }
                | TrayIconEvent::Move { rect, .. } => remember_tray_rect(tray.app_handle(), rect),
                _ => {}
            }
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                remember_tray_hint(tray.app_handle());
                toggle_panel(tray.app_handle());
            }
        });

    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true);
    }

    builder.build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    let _ = MAIN_THREAD.set(std::thread::current().id());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
                .add_directive("rmcp=off".parse().expect("valid log directive")),
        )
        .try_init();

    // Menu launches get the session PATH, which lacks the shell's additions; servers are found
    // by name on PATH, so ask the login shell before anything spawns.
    prism_core::adopt_login_shell_path();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .manage(UpdateState::default())
        .setup(|app| {
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            }

            if app.get_webview_window(PANEL_LABEL).is_none() {
                WebviewWindowBuilder::new(app, PANEL_LABEL, WebviewUrl::App("index.html".into()))
                    .title("Prism")
                    .inner_size(PANEL_SIZE.0, PANEL_SIZE.1)
                    .decorations(false)
                    .transparent(true)
                    .always_on_top(true)
                    .skip_taskbar(true)
                    .visible(false)
                    .resizable(false)
                    .build()?;
            }

            if let Some(window) = app.get_webview_window(PANEL_LABEL) {
                let _ = window.set_size(LogicalSize::new(PANEL_SIZE.0, PANEL_SIZE.1));
            }

            let (config_path, audit_path) = config_paths(app.handle())?;
            ensure_auto_open_default(&config_path);

            let gateway = tauri::async_runtime::block_on(Gateway::start(config_path, audit_path))
                .map_err(|err| {
                error!(%err, "failed to start gateway");
                err
            })?;

            app.manage(AppState {
                gateway: gateway.clone(),
            });

            recall_tray_hint(app.handle());
            build_tray(app.handle())?;
            // The tray embeds the icon a moment after it is built; read it once it has.
            #[cfg(target_os = "linux")]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    let _ = handle.run_on_main_thread(refresh_tray_icon);
                });
            }
            forward_events(app.handle().clone(), gateway);
            start_update_checks(app.handle().clone());

            // Dev affordances: `PRISM_SHOW_PANEL=1 cargo tauri dev` opens the panel without a tray
            // click; `PRISM_PIN_PANEL=1` also keeps it open when focus moves to the editor.
            if std::env::var_os("PRISM_SHOW_PANEL").is_some() || panel_pinned() {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    note_cursor_hint(&handle);
                    show_panel(&handle, "app");
                });
            }

            // Ctrl+Alt+P everywhere. Ctrl/Cmd+Shift+Space was the first choice, but that is
            // 1Password's quick-access key on every platform. `panel_shortcut` in prism.json
            // overrides it; an empty string turns it off.
            let configured = app
                .try_state::<AppState>()
                .and_then(|s| s.gateway.panel_shortcut());
            let shortcut = match configured.as_deref().map(str::trim) {
                Some("") => None,
                Some(text) => match text.parse::<Shortcut>() {
                    Ok(shortcut) => Some(shortcut),
                    Err(err) => {
                        warn!(%err, shortcut = text, "panel_shortcut is not a key combination; using the default");
                        Some(DEFAULT_SHORTCUT())
                    }
                },
                None => Some(DEFAULT_SHORTCUT()),
            };
            if let Some(shortcut) = shortcut {
                if let Err(err) = app
                    .global_shortcut()
                    .on_shortcut(shortcut, |app, _sc, event| {
                        if event.state == ShortcutState::Pressed {
                            toggle_panel(app);
                        }
                    })
                {
                    warn!(%err, "global shortcut unavailable; the tray icon still opens the panel");
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != PANEL_LABEL {
                return;
            }
            match event {
                WindowEvent::Focused(true) => {
                    SEEN_FOCUS.store(true, Ordering::SeqCst);
                }
                WindowEvent::Focused(false) => {
                    if panel_pinned()
                        || IGNORE_FOCUS_LOSS.load(Ordering::SeqCst)
                        || !SEEN_FOCUS.load(Ordering::SeqCst)
                    {
                        return;
                    }
                    let elapsed = now_ms().saturating_sub(LAST_SHOW_MS.load(Ordering::SeqCst));
                    if elapsed < 300 {
                        return;
                    }
                    hide_panel_window(window.app_handle(), "blur");
                }
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    hide_panel_window(window.app_handle(), "close");
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_servers,
            add_server,
            remove_server,
            restart_server,
            sign_in_server,
            sign_out_server,
            list_agents,
            create_manual_agent,
            replace_manual_token,
            decide_agent,
            remove_agent,
            revoke_agent_tokens,
            forget_client,
            list_signins,
            decide_signin,
            list_pending,
            decide,
            list_rules,
            delete_rule,
            add_rule,
            set_agent_policy,
            get_settings,
            set_settings,
            retry_listener,
            suggest_port,
            set_listen_port,
            set_listen_address,
            list_server_tools,
            set_tool_exposed,
            list_audit,
            list_audit_page,
            hide_panel,
            get_connect_snippet,
            get_update_status,
            check_update,
            install_update,
            get_native_status,
            set_observe_native,
            rotate_hook_token,
            get_host_hook_snippet,
            install_host_hook,
            setup_harness,
            remove_harness_setup,
            get_activity,
            export_native_report,
            export_audit,
            open_export,
            open_audit_log,
            open_mcp_log,
        ]);

    let app = match builder.build(tauri::generate_context!()) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("error while building Prism: {err}");
            std::process::exit(1);
        }
    };

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = app.try_state::<AppState>() {
                let gateway = state.gateway.clone();
                tauri::async_runtime::block_on(gateway.shutdown());
            }
        }
    });
}
