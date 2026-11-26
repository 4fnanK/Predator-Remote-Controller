//! Tailscale management through its official CLI (never arbitrary commands):
//! `status --json --peers=false` (plain `status --json` only for CLIs without `--peers`), bare
//! `up`, bare `down`, plus starting/stopping the `Tailscale` Windows service and the Tailscale
//! app (`tailscale-ipn.exe`, the GUI).
//!
//! Rules:
//! * only a *bare* `tailscale up` / `tailscale down` is ever run — any flag (even `--timeout`)
//!   disables the "bring it up without changing settings" path of the CLI;
//! * `up` is never run as SYSTEM while the node is logged out without a profile (it would start
//!   an unowned interactive registration);
//! * user-owned profiles refuse `down` from SYSTEM ("does not belong to the user"): the same bare
//!   command is then retried inside the active user's session;
//! * on Windows tailscaled stays in `NoState` until the Tailscale app of a logged-on user
//!   connects (unless Unattended mode is on): `up` starts the installed `tailscale-ipn.exe` (no
//!   arguments) in the active user's session when it is not running anywhere, and `down` closes
//!   it again — only processes named `tailscale-ipn.exe` whose image lies in the Tailscale
//!   install folder are ever terminated;
//! * only the `Tailscale` service is ever started/stopped and only `tailscaled.exe` PIDs that are
//!   still alive after the service stopped are ever terminated.

use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Deserializer};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};

use super::process::{self, ProcessOutput};
use super::sysinfo::RegRoot;
use super::{ServiceState, SessionInfo, TailscaleOpResult, TailscaleStatus, scm, session, sysinfo};
use crate::util::truncate_chars;
use crate::util::win::{OwnedHandle, WinError, wide, wide_path};

/// Windows service name of tailscaled.
pub const SERVICE_NAME: &str = "Tailscale";

const REG_KEY: &str = r"SOFTWARE\Tailscale IPN";
const CLI_EXE: &str = "tailscale.exe";
const DAEMON_EXE: &str = "tailscaled.exe";
/// The Tailscale app (GUI, tray icon) that runs in a user's session next to tailscale.exe.
const APP_EXE: &str = "tailscale-ipn.exe";

/// `status --json` without the peer map: only the local node is read, so the output stays a few
/// KB however large the tailnet is (`--peers` exists in every current CLI; verified with
/// `tailscale status --help` on 1.104).
const STATUS_ARGS: [&str; 3] = ["status", "--json", "--peers=false"];
/// Fallback for CLIs that reject `--peers` (every peer is serialised, ~1–1.5 KB each).
const STATUS_ARGS_LEGACY: [&str; 2] = ["status", "--json"];
/// Capture limit for the legacy full output (≈ 5,000+ peers); still bounded.
const LEGACY_STATUS_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
/// How many candidate `{` positions are tried when stdout carries text around the JSON.
const MAX_JSON_CANDIDATES: usize = 8;
const STATUS_TIMEOUT: Duration = Duration::from_secs(15);
const UP_TIMEOUT: Duration = Duration::from_secs(30);
const DOWN_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long `up` waits for the backend to leave NoState/Starting (the app needs a few seconds to
/// start and connect).
const READY_WAIT: Duration = Duration::from_secs(30);
const VERIFY_WAIT: Duration = Duration::from_secs(20);
const STATUS_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const PROCESS_EXIT_WAIT: Duration = Duration::from_secs(10);
/// How long `down` waits for terminated Tailscale app processes to disappear.
const APP_EXIT_WAIT: Duration = Duration::from_secs(5);
/// Exit code given to the Tailscale app processes we terminate.
const APP_KILLED_EXIT_CODE: u32 = 1;
/// Upper bound for an image path (`QueryFullProcessImageNameW`), in UTF-16 units.
const MAX_IMAGE_PATH_UNITS: usize = 32_768;
const PROCESS_POLL: Duration = Duration::from_millis(500);
/// Max characters of CLI output quoted in a step/error line.
const MAX_QUOTE: usize = 300;

/// Locate tailscale.exe: HKLM\SOFTWARE\Tailscale IPN (default value), then the Tailscale service
/// ImagePath directory, then %ProgramFiles%\Tailscale. Never relies on PATH.
pub fn find_cli() -> Option<PathBuf> {
    if let Some(p) = sysinfo::reg_get_string(RegRoot::LocalMachine, REG_KEY, None)
        .and_then(|v| dir_from_reg_value(&v))
        .and_then(|d| cli_in_dir(&d))
    {
        return Some(p);
    }
    if let Some(p) = scm::binary_path(SERVICE_NAME).and_then(|b| b.parent().and_then(cli_in_dir)) {
        return Some(p);
    }
    let program_files = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    cli_in_dir(&program_files.join("Tailscale"))
}

/// `<dir>\tailscale.exe` if `dir` is absolute and the file exists.
fn cli_in_dir(dir: &Path) -> Option<PathBuf> {
    exe_in_dir(dir, CLI_EXE)
}

/// `<dir>\<name>` if `dir` is absolute and the file exists.
fn exe_in_dir(dir: &Path, name: &str) -> Option<PathBuf> {
    if !dir.is_absolute() {
        return None;
    }
    let p = dir.join(name);
    p.is_file().then_some(p)
}

/// The installed Tailscale app: `tailscale-ipn.exe` next to the discovered tailscale.exe.
fn app_path(cli: &Path) -> Option<PathBuf> {
    exe_in_dir(cli.parent()?, APP_EXE)
}

/// Does `tailscale-ipn.exe` run in any session? (One process snapshot, no CLI call.)
fn app_is_running() -> bool {
    !process::find_processes(APP_EXE).is_empty()
}

/// The install directory from the registry `(default)` value (`C:\Program Files\Tailscale\`).
fn dir_from_reg_value(v: &str) -> Option<PathBuf> {
    let v = v.trim().trim_matches('"').trim();
    let v = v.trim_end_matches(['\\', '/']);
    if v.is_empty() {
        return None;
    }
    // Keep a drive root usable (`C:` → `C:\`).
    if v.len() == 2 && v.ends_with(':') {
        return Some(PathBuf::from(format!("{v}\\")));
    }
    Some(PathBuf::from(v))
}

/// Product version from an executable's version resource (`1.104.6`), without running it.
pub fn file_version(exe: &Path) -> Option<String> {
    let path = wide_path(exe);
    let mut ignored = 0u32;
    // SAFETY: NUL-terminated path; size query.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored) };
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `size` bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return None;
    }
    let root = wide("\\");
    let mut info: *mut core::ffi::c_void = null_mut();
    let mut len = 0u32;
    // SAFETY: `buf` holds the version resource; `info` will point inside `buf`.
    let ok = unsafe { VerQueryValueW(buf.as_ptr().cast(), root.as_ptr(), &mut info, &mut len) };
    if ok == 0 || info.is_null() || (len as usize) < std::mem::size_of::<VS_FIXEDFILEINFO>() {
        return None;
    }
    // SAFETY: VerQueryValueW("\\") returns a VS_FIXEDFILEINFO inside `buf`, which is still alive.
    let ffi = unsafe { std::ptr::read_unaligned(info.cast::<VS_FIXEDFILEINFO>()) };
    if ffi.dwSignature != 0xFEEF_04BD {
        return None;
    }
    Some(format_version(ffi.dwProductVersionMS, ffi.dwProductVersionLS))
}

/// `major.minor.build[.private]` from the packed VS_FIXEDFILEINFO words.
fn format_version(ms: u32, ls: u32) -> String {
    let (a, b, c, d) = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF);
    if d == 0 { format!("{a}.{b}.{c}") } else { format!("{a}.{b}.{c}.{d}") }
}

// ---------------------------------------------------------------------------------------------
// `tailscale status --json` parsing (only the fields we need; everything else is skipped).
// ---------------------------------------------------------------------------------------------

// Every field is read leniently: the CLI warns that its JSON "has changed between releases", so a
// field whose type changed (or that is `null`) only loses that field instead of the whole status.
// Unknown fields (e.g. a `Peer` map from the legacy output) are skipped without being stored.

#[derive(Deserialize, Default)]
#[serde(default)]
struct StatusJson {
    #[serde(rename = "BackendState", deserialize_with = "lenient")]
    backend_state: Option<String>,
    #[serde(rename = "AuthURL", deserialize_with = "lenient")]
    auth_url: Option<String>,
    #[serde(rename = "HaveNodeKey", deserialize_with = "lenient")]
    have_node_key: Option<bool>,
    #[serde(rename = "TailscaleIPs", deserialize_with = "lenient_strings")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Self", deserialize_with = "lenient")]
    self_node: Option<SelfJson>,
    #[serde(rename = "CurrentTailnet", deserialize_with = "lenient")]
    current_tailnet: Option<TailnetJson>,
    #[serde(rename = "Health", deserialize_with = "lenient_strings")]
    health: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct SelfJson {
    #[serde(rename = "HostName", deserialize_with = "lenient")]
    host_name: Option<String>,
    #[serde(rename = "TailscaleIPs", deserialize_with = "lenient_strings")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Online", deserialize_with = "lenient")]
    online: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TailnetJson {
    #[serde(rename = "Name", deserialize_with = "lenient")]
    name: Option<String>,
}

/// A field of an unexpected type (or `null`) becomes `None` instead of failing the parse.
fn lenient<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v = serde_json::Value::deserialize(d)?;
    Ok(T::deserialize(v).ok())
}

/// A JSON array of strings; non-string elements are dropped, any other value becomes `None`.
fn lenient_strings<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::Array(items) => Some(
            items
                .into_iter()
                .filter_map(|v| match v {
                    serde_json::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    })
}

/// The parts of the daemon status this module uses.
#[derive(Clone, Debug, Default, PartialEq)]
struct Backend {
    state: String,
    auth_url: Option<String>,
    have_node_key: bool,
    has_tailnet: bool,
    hostname: Option<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
    tailnet: Option<String>,
    health: Vec<String>,
    online: bool,
}

impl Backend {
    fn is_running(&self) -> bool {
        self.state == "Running"
    }
}

fn non_empty(s: String) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Candidate start offsets of the status object: every `{` that starts a line (the CLI prints the
/// object at column 0), then the first `{` anywhere; at most [`MAX_JSON_CANDIDATES`].
fn json_candidates(stdout: &str) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    let mut line_start = 0usize;
    for line in stdout.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('{') {
            out.push(line_start + (line.len() - trimmed.len()));
            if out.len() >= MAX_JSON_CANDIDATES {
                break;
            }
        }
        line_start += line.len();
    }
    if let Some(first) = stdout.find('{')
        && !out.contains(&first)
    {
        out.push(first);
    }
    out
}

/// The first JSON object at `start` (trailing text is ignored).
fn parse_object_at(stdout: &str, start: usize) -> Option<StatusJson> {
    let tail = stdout.get(start..)?;
    serde_json::Deserializer::from_str(tail).into_iter::<StatusJson>().next()?.ok()
}

/// Parse the stdout of `tailscale status --json` (tolerates text before and after the object,
/// unexpected field types and unknown fields).
fn parse_status_json(stdout: &str) -> Result<Backend, String> {
    let mut fallback = None;
    let mut chosen = None;
    for start in json_candidates(stdout) {
        let Some(j) = parse_object_at(stdout, start) else { continue };
        if j.backend_state.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            chosen = Some(j);
            break;
        }
        // An object without BackendState is only used when nothing better is found.
        fallback.get_or_insert(j);
    }
    let j = chosen.or(fallback).ok_or("no JSON status object in the output")?;
    let (host, self_ips, online) = match j.self_node {
        Some(s) => (s.host_name.and_then(non_empty), s.tailscale_ips, s.online.unwrap_or(false)),
        None => (None, None, false),
    };
    let ips = self_ips.filter(|v| !v.is_empty()).or(j.tailscale_ips).unwrap_or_default();
    let ipv4 = ips.iter().map(|ip| ip.trim()).find(|ip| ip.parse::<Ipv4Addr>().is_ok()).map(str::to_string);
    let ipv6 = ips.iter().map(|ip| ip.trim()).find(|ip| ip.parse::<Ipv6Addr>().is_ok()).map(str::to_string);
    let health = j.health.unwrap_or_default().into_iter().filter_map(non_empty).collect();
    Ok(Backend {
        state: j.backend_state.as_deref().map(str::trim).unwrap_or_default().to_string(),
        auth_url: j.auth_url.and_then(non_empty),
        have_node_key: j.have_node_key.unwrap_or(false),
        has_tailnet: j.current_tailnet.is_some(),
        hostname: host,
        ipv4,
        ipv6,
        tailnet: j.current_tailnet.and_then(|t| t.name).and_then(non_empty),
        health,
        online,
    })
}

fn apply_backend(st: &mut TailscaleStatus, b: &Backend) {
    st.backend_state = (!b.state.is_empty()).then(|| b.state.clone());
    st.connected = b.is_running();
    st.ipv4 = b.ipv4.clone();
    st.ipv6 = b.ipv6.clone();
    st.hostname = b.hostname.clone();
    st.tailnet = b.tailnet.clone();
    st.health = b.health.clone();
    st.auth_url = b.auth_url.clone();
    st.error = None;
}

/// Why `tailscale status` could not be read.
#[derive(Clone, Debug, PartialEq)]
struct QueryError {
    msg: String,
    /// Worth retrying (daemon starting, local API not reachable yet ...).
    transient: bool,
}

type BackendResult = Result<Backend, QueryError>;

fn query_backend(cli: &Path) -> BackendResult {
    let mut legacy = is_known_legacy_cli(cli);
    let mut out = run_status(cli, legacy)?;
    if !legacy && !out.timed_out && peers_flag_unsupported(&out.combined()) {
        crate::log_info!("tailscale: this CLI does not support `status --peers=false`; using the full status output");
        remember_legacy_cli(cli);
        legacy = true;
        out = run_status(cli, true)?;
    }
    let cap = if legacy { LEGACY_STATUS_CAPTURE_BYTES } else { process::MAX_CAPTURE_BYTES };
    backend_from_output(&out, cap)
}

fn run_status(cli: &Path, legacy: bool) -> Result<ProcessOutput, QueryError> {
    let r = if legacy {
        process::run_with_timeout_capped(cli, &STATUS_ARGS_LEGACY, STATUS_TIMEOUT, LEGACY_STATUS_CAPTURE_BYTES)
    } else {
        process::run_with_timeout(cli, &STATUS_ARGS, STATUS_TIMEOUT)
    };
    r.map_err(|e| QueryError { msg: format!("Could not run tailscale status: {e}"), transient: false })
}

/// Interpret a finished `status --json` run whose stdout was captured up to `cap` bytes.
fn backend_from_output(out: &ProcessOutput, cap: usize) -> BackendResult {
    if out.timed_out {
        return Err(QueryError {
            msg: format!(
                "tailscale status timed out after {} s (tailscaled may still be starting)",
                STATUS_TIMEOUT.as_secs()
            ),
            transient: true,
        });
    }
    // `status --json` exits 0 in every backend state; parse stdout whatever the exit code is.
    parse_status_json(&out.stdout).map_err(|_| {
        // The capture keeps `cap` bytes; lossy UTF-8 decoding of a cut character may add a few.
        let msg = if out.stdout.len() + 4 >= cap {
            format!("tailscale status failed: its output exceeded {} KiB and was cut off", cap / 1024)
        } else {
            format!("tailscale status failed: {}", first_meaningful_line(&out.combined()).unwrap_or("no output"))
        };
        QueryError { msg, transient: true }
    })
}

/// The Go flag package's answer to an unknown `--peers` flag.
fn peers_flag_unsupported(text: &str) -> bool {
    text.lines().any(|l| l.contains("flag provided but not defined") && l.contains("peers"))
}

/// CLI (path + version) known to reject `--peers`, so later calls go straight to the fallback.
/// Keyed by version: an upgraded CLI is probed again.
static LEGACY_CLI: Mutex<Option<String>> = Mutex::new(None);

fn cli_key(cli: &Path) -> String {
    format!("{}|{}", cli.display(), file_version(cli).unwrap_or_default())
}

fn is_known_legacy_cli(cli: &Path) -> bool {
    let known = LEGACY_CLI.lock().unwrap_or_else(|e| e.into_inner()).clone();
    // The version resource is only read once a legacy CLI has been seen at all.
    known.is_some_and(|k| k == cli_key(cli))
}

fn remember_legacy_cli(cli: &Path) {
    *LEGACY_CLI.lock().unwrap_or_else(|e| e.into_inner()) = Some(cli_key(cli));
}

/// Still starting / not reachable yet → keep waiting.
fn is_transient(r: &BackendResult) -> bool {
    match r {
        Ok(b) => matches!(b.state.as_str(), "" | "NoState" | "Starting"),
        Err(e) => e.transient,
    }
}

/// Re-run `status` every 2 s until `done` or `max` elapsed; returns the last result.
fn wait_for(cli: &Path, max: Duration, done: impl Fn(&BackendResult) -> bool) -> BackendResult {
    let deadline = Instant::now() + max;
    loop {
        let r = query_backend(cli);
        let now = Instant::now();
        if done(&r) || now >= deadline {
            return r;
        }
        std::thread::sleep(STATUS_RETRY_INTERVAL.min(deadline - now));
    }
}

// ---------------------------------------------------------------------------------------------
// CLI output helpers.
// ---------------------------------------------------------------------------------------------

/// The CLI refused the request because the current profile belongs to another Windows user.
fn is_ownership_error(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    ["does not belong to the user", "already in use by", "access denied", "access is denied"]
        .iter()
        .any(|needle| t.contains(needle))
}

/// First non-empty line that is not part of an auth/approve URL block.
fn first_meaningful_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|l| {
        !l.is_empty() && !l.starts_with("To authenticate") && !l.starts_with("To approve") && !l.starts_with("https://")
    })
}

/// What a `tailscale up` run printed.
#[derive(Clone, Debug, Default, PartialEq)]
struct UpOutput {
    auth_url: Option<String>,
    approve_url: Option<String>,
    success: bool,
    error: Option<String>,
}

fn parse_up_output(text: &str) -> UpOutput {
    let mut out = UpOutput::default();
    let mut expect: Option<bool> = None; // Some(true) = auth URL next, Some(false) = approve URL next
    for line in text.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("To authenticate, visit") {
            expect = Some(true);
            continue;
        }
        if line.starts_with("To approve your machine, visit") {
            expect = Some(false);
            continue;
        }
        if let Some(is_auth) = expect.take()
            && line.starts_with("https://")
        {
            let url = line.split_whitespace().next().unwrap_or(line).to_string();
            if is_auth {
                out.auth_url = Some(url)
            } else {
                out.approve_url = Some(url)
            }
            continue;
        }
        if line == "Success." {
            out.success = true;
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if out.error.is_none()
            && (lower.starts_with("error")
                || lower.contains("failed")
                || lower.contains("not allowed")
                || is_ownership_error(line))
        {
            out.error = Some(truncate_chars(line, MAX_QUOTE));
        }
    }
    out
}

/// Is tailscaled (the `Tailscale` service) possibly running, i.e. worth asking the CLI?
fn daemon_may_run(service: &ServiceState) -> bool {
    matches!(service, ServiceState::Running | ServiceState::Unknown)
}

/// Status while the service is not running: no daemon → no backend state and disconnected.
/// `backend_state` stays `None` (never a service label, which consumers would render as an
/// unknown 🟡 backend state); the UI shows 🔴 Disconnected next to the service state.
fn without_daemon(mut st: TailscaleStatus) -> TailscaleStatus {
    st.backend_state = None;
    st.connected = false;
    st.ipv4 = None;
    st.ipv6 = None;
    st.auth_url = None;
    st.health.clear();
    st.error = None;
    st
}

/// State for messages: the backend state, else the service state when the daemon is not running.
fn state_text(st: &TailscaleStatus) -> String {
    match st.backend_state.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_string(),
        None if !daemon_may_run(&st.service) => format!("service {}", st.service.label().to_ascii_lowercase()),
        None => "unknown".into(),
    }
}

/// What `up` should do given the (ready) backend status.
#[derive(Clone, Debug, PartialEq)]
enum UpDecision {
    AlreadyConnected,
    /// Logged out with no profile/node key: never run `up` as SYSTEM.
    NeedsLoginNoProfile {
        auth_url: Option<String>,
    },
    NeedsMachineAuth,
    RunUp,
}

fn decide_up(b: Option<&Backend>) -> UpDecision {
    let Some(b) = b else {
        return UpDecision::RunUp;
    };
    match b.state.as_str() {
        "Running" => UpDecision::AlreadyConnected,
        "NeedsLogin" if !b.have_node_key && !b.has_tailnet => {
            UpDecision::NeedsLoginNoProfile { auth_url: b.auth_url.clone() }
        }
        "NeedsMachineAuth" => UpDecision::NeedsMachineAuth,
        _ => UpDecision::RunUp,
    }
}

// ---------------------------------------------------------------------------------------------
// The Tailscale app (tailscale-ipn.exe).
// ---------------------------------------------------------------------------------------------

/// What `up` does about the Tailscale app.
#[derive(Clone, Debug, PartialEq)]
enum AppPlan {
    /// tailscale-ipn.exe already runs (in some session): nothing to start.
    AlreadyRunning,
    /// Start it in this session for this user.
    Launch { session_id: u32, user: String },
    /// Nobody is logged on: only Unattended mode can bring the backend up.
    NoUser,
}

/// `user` = the active user session (only looked up while the app is not running).
fn plan_app(app_running: bool, user: Option<SessionInfo>) -> AppPlan {
    if app_running {
        return AppPlan::AlreadyRunning;
    }
    match user {
        Some(s) => AppPlan::Launch { session_id: s.id, user: s.user },
        None => AppPlan::NoUser,
    }
}

/// Carry out `plan` (never fatal). Returns true when the app was started by this call.
fn start_app(cli: &Path, plan: &AppPlan, steps: &mut Steps) -> bool {
    let (session_id, user) = match plan {
        AppPlan::AlreadyRunning => {
            steps.ok("Tailscale app is already running");
            return false;
        }
        AppPlan::NoUser => {
            steps.info("No user is logged in — relying on Tailscale Unattended mode");
            return false;
        }
        AppPlan::Launch { session_id, user } => (*session_id, user),
    };
    let Some(app) = app_path(cli) else {
        steps.warn(format!("The Tailscale app ({APP_EXE}) was not found next to tailscale.exe — not started"));
        return false;
    };
    match session::launch_in_session(session_id, &app, &[]) {
        Ok(pid) => {
            crate::log_info!("tailscale: started {APP_EXE} (pid {pid}) in session {session_id}");
            steps.ok(format!("Tailscale app started for {user}"));
            true
        }
        Err(e) => {
            crate::log_warn!("tailscale: could not start {APP_EXE} in session {session_id}: {e}");
            steps.warn(format!("Could not start the Tailscale app for {user}: {}", truncate_chars(&e, MAX_QUOTE)));
            false
        }
    }
}

/// Is the Tailscale app (probably) still connecting to tailscaled? True right after we started
/// it, and when the service was just started while the app was already running (a running app
/// reconnects to a fresh service by itself, which takes a moment too).
fn app_is_connecting(app_started: bool, service_started: bool, app_was_running: bool) -> bool {
    app_started || (service_started && app_was_running)
}

/// Done waiting for the backend after the service/app start? NoState/Starting (and a daemon that
/// cannot be reached yet) are transient. While the app is still connecting, a logged-out backend
/// without a profile is too: that is tailscaled's idle placeholder until the app's user profile
/// is loaded.
fn backend_ready(r: &BackendResult, app_connecting: bool) -> bool {
    if is_transient(r) {
        return false;
    }
    match r {
        Ok(b) if app_connecting => !matches!(decide_up(Some(b)), UpDecision::NeedsLoginNoProfile { .. }),
        _ => true,
    }
}

/// Warning when the backend is still starting after [`READY_WAIT`], with a hint when the app
/// cannot be what connects it.
fn still_starting_text(state: &str, plan: &AppPlan, app_running: bool) -> String {
    let state = if state.trim().is_empty() { "unknown" } else { state.trim() };
    let hint = match plan {
        AppPlan::NoUser => " — nobody is logged in to Windows, so only Run unattended can connect it",
        _ if !app_running => " — the Tailscale app is not running",
        _ => "",
    };
    format!("Tailscale is still starting after {} s (state: {state}){hint}", READY_WAIT.as_secs())
}

/// What happened to one tailscale-ipn.exe process during `down`.
#[derive(Clone, Debug, PartialEq)]
enum AppKill {
    Terminated,
    /// It exited before it could be terminated.
    Gone,
    /// Not the installed Tailscale app (image outside the install folder): left alone.
    Foreign(String),
    Failed(String),
}

/// Comparable form of a directory path: `\` separators, no `\\?\` prefix, no trailing `\`,
/// lower case (Windows paths are case-insensitive).
fn dir_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.trim_end_matches('\\').to_lowercase()
}

/// Is `image` (a full process image path) the installed Tailscale app, i.e. exactly
/// `<install_dir>\tailscale-ipn.exe`? When the spellings differ (8.3 short names such as
/// `C:\PROGRA~1\TAILSC~1`, a junction or a SUBST drive in one of the two paths) the final paths
/// of both are compared; a path that does not exist never matches that way.
fn is_installed_app(image: &Path, install_dir: &Path) -> bool {
    if !install_dir.is_absolute() {
        return false;
    }
    if same_app_path(image, install_dir) {
        return true;
    }
    match (std::fs::canonicalize(image), std::fs::canonicalize(install_dir)) {
        (Ok(image), Ok(dir)) => same_app_path(&image, &dir),
        _ => false,
    }
}

/// Textual check: `image` is `<dir>\tailscale-ipn.exe` (case-insensitive, `\\?\` and `/` tolerated).
fn same_app_path(image: &Path, dir: &Path) -> bool {
    let name_ok = image.file_name().is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(APP_EXE));
    let dir = dir_key(dir);
    name_ok && !dir.is_empty() && image.parent().is_some_and(|p| dir_key(p) == dir)
}

/// Step lines for closing the app: `results` per PID found, `still` = PIDs alive afterwards.
fn report_app_close(results: &[(u32, AppKill)], still: &[u32], steps: &mut Steps) {
    if results.is_empty() && still.is_empty() {
        steps.ok("Tailscale app is not running");
        return;
    }
    let foreign: Vec<String> = results
        .iter()
        .filter_map(|(pid, k)| match k {
            AppKill::Foreign(path) => Some(format!("PID {pid}: {}", truncate_chars(path, MAX_QUOTE))),
            _ => None,
        })
        .collect();
    let failed: Vec<String> = results
        .iter()
        .filter_map(|(pid, k)| match k {
            AppKill::Failed(e) => Some(format!("PID {pid}: {}", truncate_chars(e, MAX_QUOTE))),
            _ => None,
        })
        .collect();
    if !foreign.is_empty() {
        steps.warn(format!("Left {APP_EXE} alone — not the installed Tailscale app ({})", foreign.join("; ")));
    }
    if still.is_empty() {
        steps.ok("Tailscale app closed");
        return;
    }
    if !failed.is_empty() {
        steps.fail(format!("Could not close the Tailscale app: {}", failed.join("; ")));
    }
    steps.fail(format!("The Tailscale app is still running (PID {})", join_pids(still)));
}

/// Result of `down`: Ok when the service is stopped and neither tailscaled.exe nor the Tailscale
/// app is left, else the most relevant error.
fn down_outcome(
    service: &ServiceState,
    stop_error: Option<String>,
    daemon_left: &[u32],
    app_running: bool,
    app_left: &[u32],
) -> Result<(), String> {
    if *service == ServiceState::Stopped && daemon_left.is_empty() && !app_running {
        return Ok(());
    }
    Err(if let Some(e) = stop_error {
        e
    } else if !daemon_left.is_empty() {
        format!("tailscaled.exe is still running (PID {})", join_pids(daemon_left))
    } else if *service != ServiceState::Stopped {
        format!("The Tailscale service is {}", service.label())
    } else if app_left.is_empty() {
        format!("The Tailscale app ({APP_EXE}) is still running")
    } else {
        format!("The Tailscale app ({APP_EXE}) is still running (PID {})", join_pids(app_left))
    })
}

// ---------------------------------------------------------------------------------------------
// Public operations.
// ---------------------------------------------------------------------------------------------

/// Step log with ✅ / ℹ️ / ⚠️ / ❌ prefixes.
#[derive(Default)]
struct Steps(Vec<String>);

impl Steps {
    fn ok(&mut self, s: impl AsRef<str>) {
        self.0.push(format!("✅ {}", s.as_ref()));
    }
    fn info(&mut self, s: impl AsRef<str>) {
        self.0.push(format!("ℹ️ {}", s.as_ref()));
    }
    fn warn(&mut self, s: impl AsRef<str>) {
        self.0.push(format!("⚠️ {}", s.as_ref()));
    }
    fn fail(&mut self, s: impl AsRef<str>) {
        self.0.push(format!("❌ {}", s.as_ref()));
    }
}

fn op_result(success: bool, steps: Steps, status: TailscaleStatus, error: Option<String>) -> TailscaleOpResult {
    TailscaleOpResult { success, steps: steps.0, status, error }
}

/// Installation facts and whether the app runs (no CLI call).
fn base_status() -> TailscaleStatus {
    let exe = find_cli();
    let (service, _) = scm::query(SERVICE_NAME);
    TailscaleStatus {
        installed: exe.is_some() || service != ServiceState::NotInstalled,
        version: exe.as_deref().and_then(file_version),
        exe_path: exe,
        service,
        app_running: app_is_running(),
        ..Default::default()
    }
}

/// Combine installation facts with a backend query result.
fn status_from(mut st: TailscaleStatus, backend: &BackendResult) -> TailscaleStatus {
    match backend {
        Ok(b) => apply_backend(&mut st, b),
        Err(e) => st.error = Some(e.msg.clone()),
    }
    st
}

/// Installed? service state? backend state? IPs?
pub fn status() -> TailscaleStatus {
    let mut st = base_status();
    if !st.installed {
        st.error = Some("Tailscale is not installed on this PC.".into());
        return st;
    }
    let Some(cli) = st.exe_path.clone() else {
        st.error =
            Some("tailscale.exe was not found (checked the registry, the service path and Program Files).".into());
        return st;
    };
    if !daemon_may_run(&st.service) {
        return without_daemon(st);
    }
    let backend = query_backend(&cli);
    status_from(st, &backend)
}

/// Who finally ran a CLI command (None = this process / SYSTEM).
type CliRun = (ProcessOutput, Option<String>);

/// Run a fixed CLI command; on a profile-ownership refusal retry the same command inside the
/// active user's session.
fn run_cli_with_owner_fallback(
    cli: &Path,
    args: &[&str],
    timeout: Duration,
    steps: &mut Steps,
) -> Result<CliRun, String> {
    let label = format!("tailscale {}", args.join(" "));
    let out = process::run_with_timeout(cli, args, timeout).map_err(|e| format!("{label} could not be run: {e}"))?;
    let text = out.combined();
    if out.timed_out || !is_ownership_error(&text) {
        return Ok((out, None));
    }
    let reason = first_meaningful_line(&text).map(|l| truncate_chars(l, MAX_QUOTE)).unwrap_or_default();
    let Some(user) = session::active_user_session() else {
        steps.warn(format!("{label} was refused for the service account ({reason}) and no user is logged in to retry"));
        return Ok((out, None));
    };
    steps.warn(format!("{label} was refused for the service account ({reason}) — retrying as {}", user.user));
    match session::run_as_session_user(user.id, cli, args, timeout) {
        Ok(o) => Ok((o, Some(user.user))),
        Err(e) => {
            steps.warn(format!("Retrying as {} failed: {e}", user.user));
            Ok((out, None))
        }
    }
}

fn as_who(who: &Option<String>) -> String {
    who.as_ref().map(|u| format!(" (as {u})")).unwrap_or_default()
}

/// Start the service if needed, start the Tailscale app in the active user's session if it is
/// not running, wait for the backend, bring Tailscale up (bare `tailscale up`), verify Running.
pub fn up() -> TailscaleOpResult {
    let r = up_inner();
    crate::log_info!("tailscale up: success={} state={}", r.success, r.status.backend_state.as_deref().unwrap_or("-"));
    r
}

fn up_inner() -> TailscaleOpResult {
    let mut steps = Steps::default();
    let mut base = base_status();
    let Some(cli) = base.exe_path.clone() else {
        let msg = "Tailscale is not installed (tailscale.exe not found).".to_string();
        steps.fail(&msg);
        return op_result(false, steps, base, Some(msg));
    };

    // 1. Service.
    let mut service_started = false;
    match base.service {
        ServiceState::NotInstalled => {
            let msg = "The Tailscale service is not installed — reinstall Tailscale.".to_string();
            steps.fail(&msg);
            return op_result(false, steps, base, Some(msg));
        }
        ServiceState::Running => steps.ok("Tailscale service is running"),
        _ => match scm::start_and_wait(SERVICE_NAME, SERVICE_TIMEOUT) {
            Ok(()) => {
                steps.ok("Tailscale service started");
                service_started = true;
            }
            Err(e) => {
                steps.fail(format!("Could not start the Tailscale service: {e}"));
                return op_result(false, steps, status(), Some(e));
            }
        },
    }
    base.service = scm::query(SERVICE_NAME).0;

    // 2. The Tailscale app: without it (and without Unattended mode) tailscaled stays in NoState.
    let user = if base.app_running { None } else { session::active_user_session() };
    let plan = plan_app(base.app_running, user);
    let app_started = start_app(&cli, &plan, &mut steps);
    let app_connecting = app_is_connecting(app_started, service_started, base.app_running);

    // 3. Wait until the backend is past NoState/Starting (≤ 30 s, status every 2 s).
    let ready = wait_for(&cli, READY_WAIT, |r| backend_ready(r, app_connecting));
    base.app_running = app_is_running();
    match &ready {
        Ok(b) if is_transient(&ready) => steps.warn(still_starting_text(&b.state, &plan, base.app_running)),
        Err(e) => steps.warn(format!("Could not read the Tailscale status: {}", e.msg)),
        Ok(_) => {}
    }

    // 4. Decide.
    match decide_up(ready.as_ref().ok()) {
        UpDecision::AlreadyConnected => {
            steps.ok("Tailscale is already connected");
            let st = status_from(base, &ready);
            return op_result(st.connected, steps, st, None);
        }
        UpDecision::NeedsLoginNoProfile { auth_url } => {
            let mut msg = "Tailscale is not logged in. Log in once on the PC or enable Run unattended \
                           (Tailscale menu → Preferences → Run unattended)."
                .to_string();
            if let Some(u) = &auth_url {
                msg.push_str(&format!(" Login link (whoever opens it binds this PC): {u}"));
            }
            steps.fail(&msg);
            let st = status_from(base, &ready);
            return op_result(false, steps, st, Some(msg));
        }
        UpDecision::NeedsMachineAuth => {
            let msg = "This PC is waiting for approval in the Tailscale admin console.".to_string();
            steps.fail(&msg);
            let st = status_from(base, &ready);
            return op_result(false, steps, st, Some(msg));
        }
        UpDecision::RunUp => {}
    }

    // 5. Bare `tailscale up` (no flags!).
    let (up_out, up_failed_hard) = match run_cli_with_owner_fallback(&cli, &["up"], UP_TIMEOUT, &mut steps) {
        Err(e) => {
            steps.fail(&e);
            (UpOutput { error: Some(e), ..Default::default() }, true)
        }
        Ok((out, who)) => {
            let parsed = parse_up_output(&out.combined());
            let who = as_who(&who);
            let hard = if out.timed_out {
                if let Some(u) = &parsed.auth_url {
                    steps.warn(format!("tailscale up{who} is waiting for login — open: {u}"));
                } else if let Some(u) = &parsed.approve_url {
                    steps.warn(format!("tailscale up{who} is waiting for admin approval: {u}"));
                } else {
                    steps.warn(format!("tailscale up{who} did not finish within {} s", UP_TIMEOUT.as_secs()));
                }
                false
            } else if parsed.success {
                steps.ok(format!("tailscale up{who}: Success."));
                false
            } else if out.success() {
                steps.ok(format!("tailscale up{who} completed"));
                false
            } else {
                let why = parsed
                    .error
                    .clone()
                    .or_else(|| first_meaningful_line(&out.combined()).map(|l| truncate_chars(l, MAX_QUOTE)))
                    .unwrap_or_else(|| format!("exit code {}", out.exit_code.unwrap_or(0)));
                steps.fail(format!("tailscale up{who} failed: {why}"));
                true
            };
            (parsed, hard)
        }
    };

    // 6. Verify (≤ 20 s) — stop early on states that need a human.
    let verify_wait = if up_failed_hard { Duration::ZERO } else { VERIFY_WAIT };
    let verified = wait_for(
        &cli,
        verify_wait,
        |r| matches!(r, Ok(b) if matches!(b.state.as_str(), "Running" | "NeedsLogin" | "NeedsMachineAuth")),
    );
    base.service = scm::query(SERVICE_NAME).0;
    base.app_running = app_is_running();
    if app_started && !base.app_running {
        steps.warn("The Tailscale app exited right after it was started");
    }
    let mut st = status_from(base, &verified);
    if st.auth_url.is_none() {
        st.auth_url = up_out.auth_url.clone();
    }
    if st.connected {
        let ip = st.ipv4.as_deref().map(|ip| format!(" — Tailscale IP {ip}")).unwrap_or_default();
        steps.ok(format!("Connected{ip}"));
        return op_result(true, steps, st, None);
    }
    let state = state_text(&st);
    let error = if let Some(u) = &st.auth_url {
        format!("Tailscale needs you to log in: open {u}")
    } else if let Some(u) = &up_out.approve_url {
        format!("This PC needs admin approval: {u}")
    } else if let Some(e) = &up_out.error {
        e.clone()
    } else if let Some(e) = &st.error {
        e.clone()
    } else {
        format!("Tailscale did not reach the Running state (state: {state})")
    };
    steps.fail(format!("Not connected (state: {state})"));
    op_result(false, steps, st, Some(error))
}

/// Disconnect (bare `tailscale down`), close the Tailscale app, stop the service, make sure
/// tailscaled.exe exited, verify.
pub fn down() -> TailscaleOpResult {
    let r = down_inner();
    crate::log_info!(
        "tailscale down: success={} service={} app_running={}",
        r.success,
        r.status.service.label(),
        r.status.app_running
    );
    r
}

fn down_inner() -> TailscaleOpResult {
    let mut steps = Steps::default();
    let base = base_status();
    let Some(cli) = base.exe_path.clone() else {
        let msg = "Tailscale is not installed (tailscale.exe not found).".to_string();
        steps.fail(&msg);
        return op_result(false, steps, base, Some(msg));
    };
    if base.service == ServiceState::NotInstalled {
        let msg = "The Tailscale service is not installed.".to_string();
        steps.fail(&msg);
        return op_result(false, steps, base, Some(msg));
    }

    // 1. Bare `tailscale down` while the daemon runs. Failure is recorded, never fatal.
    if daemon_may_run(&base.service) {
        match run_cli_with_owner_fallback(&cli, &["down"], DOWN_TIMEOUT, &mut steps) {
            Err(e) => steps.warn(format!("{e} — stopping the service anyway")),
            Ok((out, who)) => {
                let who = as_who(&who);
                let text = out.combined();
                if text.contains("already stopped") {
                    steps.ok("Tailscale was already disconnected");
                } else if out.timed_out {
                    steps.warn(format!(
                        "tailscale down{who} did not finish within {} s — stopping the service anyway",
                        DOWN_TIMEOUT.as_secs()
                    ));
                } else if out.success() {
                    steps.ok(format!("tailscale down{who}: disconnected"));
                } else {
                    let why = first_meaningful_line(&text)
                        .map(|l| truncate_chars(l, MAX_QUOTE))
                        .unwrap_or_else(|| format!("exit code {}", out.exit_code.unwrap_or(0)));
                    steps.warn(format!("tailscale down{who} failed: {why} — stopping the service anyway"));
                }
            }
        }
    } else {
        steps.ok(format!("Tailscale service is not running ({})", base.service.label()));
    }

    // 2. Close the Tailscale app in every session (only the installed tailscale-ipn.exe).
    let app_left = close_app(&cli, &mut steps);

    // 3. Stop the Tailscale service (and only that service).
    let stop_error = match scm::stop_and_wait(SERVICE_NAME, SERVICE_TIMEOUT) {
        Ok(()) => {
            steps.ok("Tailscale service stopped");
            None
        }
        Err(e) => {
            steps.fail(format!("Could not stop the Tailscale service: {e}"));
            Some(e)
        }
    };

    // 4. Make sure no tailscaled.exe survives a stopped service.
    let (svc_state, _) = scm::query(SERVICE_NAME);
    let leftovers = if matches!(svc_state, ServiceState::Stopped | ServiceState::StopPending) {
        let leftovers = wait_processes_gone(DAEMON_EXE, PROCESS_EXIT_WAIT);
        if leftovers.is_empty() {
            steps.ok("No tailscaled.exe process left");
            leftovers
        } else {
            let mut killed = Vec::new();
            let mut failed = Vec::new();
            for pid in &leftovers {
                match process::terminate_process(*pid) {
                    Ok(()) => killed.push(pid.to_string()),
                    Err(e) => failed.push(format!("PID {pid}: {e}")),
                }
            }
            if !killed.is_empty() {
                steps.warn(format!(
                    "Terminated {} leftover tailscaled.exe process(es) (PID {})",
                    killed.len(),
                    killed.join(", ")
                ));
            }
            if !failed.is_empty() {
                steps.fail(format!("Could not terminate tailscaled.exe: {}", failed.join("; ")));
            }
            let still = wait_processes_gone(DAEMON_EXE, Duration::from_secs(3));
            if !still.is_empty() {
                steps.fail(format!("tailscaled.exe is still running (PID {})", join_pids(&still)));
            }
            still
        }
    } else {
        steps.fail(format!("The Tailscale service is still {} — tailscaled.exe was left alone", svc_state.label()));
        process::find_processes(DAEMON_EXE)
    };

    // 5. Final verified status (service stopped, app not running, disconnected).
    let st = status();
    let outcome = down_outcome(&st.service, stop_error, &leftovers, st.app_running, &app_left);
    if outcome.is_ok() {
        steps.ok("Tailscale is down (app closed, service stopped, disconnected)");
    }
    op_result(outcome.is_ok(), steps, st, outcome.err())
}

/// Terminate every installed tailscale-ipn.exe (any session) and wait until they are gone
/// (≤ 5 s in total). Returns the PIDs of tailscale-ipn.exe processes still running afterwards.
fn close_app(cli: &Path, steps: &mut Steps) -> Vec<u32> {
    let pids = process::find_processes(APP_EXE);
    if pids.is_empty() {
        report_app_close(&[], &[], steps);
        return pids;
    }
    let install_dir = cli.parent().unwrap_or(cli);
    let deadline = Instant::now() + APP_EXIT_WAIT;
    let results: Vec<(u32, AppKill)> =
        pids.iter().map(|&pid| (pid, terminate_app(pid, install_dir, deadline))).collect();
    for (pid, r) in &results {
        crate::log_info!("tailscale: {APP_EXE} pid {pid}: {r:?}");
    }
    // Only the processes terminated here are waited for: a copy that was left alone (outside the
    // install folder) would otherwise hold `down` for the whole wait.
    let killed: Vec<u32> = results.iter().filter(|(_, r)| *r == AppKill::Terminated).map(|(pid, _)| *pid).collect();
    let still = poll_processes(APP_EXE, deadline, |pids| !pids.iter().any(|p| killed.contains(p)));
    report_app_close(&results, &still, steps);
    still
}

/// Terminate one tailscale-ipn.exe process after checking (on the same handle, so a reused PID
/// cannot be hit) that its image is the installed Tailscale app, then wait on that handle (no
/// polling) until it has exited or `deadline` has passed.
fn terminate_app(pid: u32, install_dir: &Path, deadline: Instant) -> AppKill {
    if matches!(pid, 0 | 4) {
        return AppKill::Failed(format!("refusing to terminate system process {pid}"));
    }
    let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
    // SAFETY: plain call; the handle is owned below.
    let raw = unsafe { OpenProcess(access, 0, pid) };
    if raw.is_null() {
        let e = WinError::last("OpenProcess");
        // No such process (any more).
        return if e.code == ERROR_INVALID_PARAMETER { AppKill::Gone } else { AppKill::Failed(e.to_string()) };
    }
    let h = OwnedHandle(raw);
    let image = match process_image_path(h.raw()) {
        Ok(p) => p,
        Err(e) => return AppKill::Failed(format!("cannot read its program path: {e}")),
    };
    if !is_installed_app(&image, install_dir) {
        return AppKill::Foreign(image.display().to_string());
    }
    // SAFETY: valid handle opened with PROCESS_TERMINATE.
    if unsafe { TerminateProcess(h.raw(), APP_KILLED_EXIT_CODE) } == 0 {
        let e = WinError::last("TerminateProcess");
        // A process that is already exiting refuses to be terminated.
        if process::wait_handle(h.raw(), Duration::ZERO) == process::WaitOutcome::Signaled {
            return AppKill::Gone;
        }
        return AppKill::Failed(e.to_string());
    }
    // TerminateProcess only starts the termination.
    let left = deadline.saturating_duration_since(Instant::now());
    let waited = process::wait_handle(h.raw(), left);
    if waited != process::WaitOutcome::Signaled {
        crate::log_warn!("tailscale: {APP_EXE} pid {pid} has not exited yet after TerminateProcess ({waited:?})");
    }
    AppKill::Terminated
}

/// Full Win32 image path of a process (handle with PROCESS_QUERY_LIMITED_INFORMATION).
fn process_image_path(h: HANDLE) -> Result<PathBuf, WinError> {
    let mut cap = 512usize;
    loop {
        let mut buf = vec![0u16; cap];
        let mut len = cap as u32;
        // SAFETY: `buf` holds `len` writable UTF-16 units; on success `len` is the length
        // written (without the NUL).
        if unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } != 0 {
            buf.truncate((len as usize).min(cap));
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        let e = WinError::last("QueryFullProcessImageNameW");
        if e.code != ERROR_INSUFFICIENT_BUFFER || cap >= MAX_IMAGE_PATH_UNITS {
            return Err(e);
        }
        cap = (cap * 4).min(MAX_IMAGE_PATH_UNITS);
    }
}

fn join_pids(pids: &[u32]) -> String {
    pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// Poll (every 500 ms, at most `max`) until no process named `name` runs; returns the PIDs still
/// alive.
fn wait_processes_gone(name: &str, max: Duration) -> Vec<u32> {
    poll_processes(name, Instant::now() + max, |pids| pids.is_empty())
}

/// Take a snapshot of the processes named `name` every 500 ms until `done(pids)` or `deadline`;
/// returns the last snapshot.
fn poll_processes(name: &str, deadline: Instant, done: impl Fn(&[u32]) -> bool) -> Vec<u32> {
    loop {
        let pids = process::find_processes(name);
        let now = Instant::now();
        if done(&pids) || now >= deadline {
            return pids;
        }
        std::thread::sleep(PROCESS_POLL.min(deadline - now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{
      "Version": "1.104.6-t3b273a64c-gdf9d2ed85",
      "TUN": true,
      "BackendState": "Running",
      "HaveNodeKey": true,
      "AuthURL": "",
      "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::6f01:6667"],
      "Self": {
        "ID": "nAbCdEf123CNTRL",
        "PublicKey": "nodekey:0123456789abcdef",
        "HostName": "DESKTOP-01",
        "DNSName": "desktop-01.tail1234.ts.net.",
        "OS": "windows",
        "TailscaleIPs": ["100.101.102.103", "fd7a:115c:a1e0::6f01:6667"],
        "Online": true,
        "ExitNode": false
      },
      "Health": [],
      "MagicDNSSuffix": "tail1234.ts.net",
      "CurrentTailnet": {"Name": "user@example.com", "MagicDNSSuffix": "tail1234.ts.net", "MagicDNSEnabled": true},
      "Peer": {
        "nodekey:fedcba": {"HostName": "phone", "TailscaleIPs": ["100.64.0.2"], "Online": false}
      },
      "User": {"1234": {"ID": 1234, "LoginName": "user@example.com", "DisplayName": "User"}},
      "ClientVersion": null
    }"#;

    const STOPPED: &str = r#"{"Version":"1.104.6","BackendState":"Stopped","HaveNodeKey":true,"AuthURL":"",
      "TailscaleIPs":["100.101.102.103"],
      "Self":{"HostName":"DESKTOP-01","TailscaleIPs":["100.101.102.103"],"Online":false},
      "Health":["Tailscale is stopped."],
      "CurrentTailnet":{"Name":"user@example.com"},"Peer":null,"User":null}"#;

    // Logged out, no profile: HaveNodeKey omitted (omitempty), CurrentTailnet null.
    const NEEDS_LOGIN: &str = r#"{"Version":"1.104.6","BackendState":"NeedsLogin","AuthURL":"",
      "TailscaleIPs":null,
      "Self":{"ID":"","PublicKey":"nodekey:0000000000000000","HostName":"DESKTOP-01","TailscaleIPs":null,"Online":false},
      "Health":["You are logged out."],"MagicDNSSuffix":"","CurrentTailnet":null,"Peer":null,"User":null}"#;

    const NO_STATE: &str = r#"{"Version":"1.104.6","BackendState":"NoState","AuthURL":"","TailscaleIPs":null,
      "Self":null,"Health":null,"CurrentTailnet":null}"#;

    #[test]
    fn parse_running() {
        let b = parse_status_json(RUNNING).unwrap();
        assert_eq!(b.state, "Running");
        assert!(b.is_running() && b.have_node_key && b.has_tailnet && b.online);
        assert_eq!(b.ipv4.as_deref(), Some("100.101.102.103"));
        assert_eq!(b.ipv6.as_deref(), Some("fd7a:115c:a1e0::6f01:6667"));
        assert_eq!(b.hostname.as_deref(), Some("DESKTOP-01"));
        assert_eq!(b.tailnet.as_deref(), Some("user@example.com"));
        assert!(b.health.is_empty());
        assert_eq!(b.auth_url, None);

        let mut st = TailscaleStatus::default();
        apply_backend(&mut st, &b);
        assert!(st.connected);
        assert_eq!(st.backend_state.as_deref(), Some("Running"));
        assert_eq!(st.ipv4.as_deref(), Some("100.101.102.103"));
    }

    #[test]
    fn parse_stopped() {
        let b = parse_status_json(STOPPED).unwrap();
        assert_eq!(b.state, "Stopped");
        assert!(!b.is_running() && b.has_tailnet);
        assert_eq!(b.health, vec!["Tailscale is stopped.".to_string()]);
        assert_eq!(decide_up(Some(&b)), UpDecision::RunUp);
    }

    #[test]
    fn parse_needs_login_without_profile() {
        let b = parse_status_json(NEEDS_LOGIN).unwrap();
        assert_eq!(b.state, "NeedsLogin");
        assert!(!b.have_node_key && !b.has_tailnet);
        assert_eq!(b.ipv4, None);
        assert_eq!(decide_up(Some(&b)), UpDecision::NeedsLoginNoProfile { auth_url: None });

        let with_url = NEEDS_LOGIN.replace(r#""AuthURL":"""#, r#""AuthURL":"https://login.tailscale.com/a/1a2b3c4d""#);
        let b = parse_status_json(&with_url).unwrap();
        assert_eq!(
            decide_up(Some(&b)),
            UpDecision::NeedsLoginNoProfile { auth_url: Some("https://login.tailscale.com/a/1a2b3c4d".into()) }
        );
        // Expired key but a profile exists → bare up is allowed.
        let with_profile = NEEDS_LOGIN.replace(r#""CurrentTailnet":null"#, r#""CurrentTailnet":{"Name":"t"}"#);
        assert_eq!(decide_up(Some(&parse_status_json(&with_profile).unwrap())), UpDecision::RunUp);
    }

    #[test]
    fn parse_no_state_is_transient() {
        let b = parse_status_json(NO_STATE).unwrap();
        assert_eq!(b.state, "NoState");
        assert_eq!(b.hostname, None);
        assert!(b.health.is_empty());
        assert!(is_transient(&Ok(b)));
        assert!(!is_transient(&Ok(parse_status_json(RUNNING).unwrap())));
        assert!(is_transient(&Err(QueryError { msg: "x".into(), transient: true })));
        assert!(!is_transient(&Err(QueryError { msg: "x".into(), transient: false })));
    }

    #[test]
    fn parse_tolerates_noise_and_rejects_garbage() {
        let noisy = format!("Warning: client version mismatch\n{RUNNING}\n");
        assert_eq!(parse_status_json(&noisy).unwrap().state, "Running");
        assert!(parse_status_json("failed to connect to local tailscaled; it doesn't appear to be running").is_err());
        assert!(parse_status_json("} {").is_err());
        assert!(parse_status_json("{ not json }").is_err());
        assert!(parse_status_json("").is_err());
    }

    #[test]
    fn health_list() {
        let j = r#"{"BackendState":"Running","Health":["  ","Some peers are advertising routes but --accept-routes is false",
            "Tailscale could not connect to the 'nyc' DERP home region"]}"#;
        let b = parse_status_json(j).unwrap();
        assert_eq!(b.health.len(), 2);
        assert!(b.health[0].contains("accept-routes"));
        assert!(b.health[1].contains("DERP"));
    }

    #[test]
    fn up_output_with_auth_url() {
        let stderr = "\nTo authenticate, visit:\n\n\thttps://login.tailscale.com/a/5e6f7a8b9c\n\n";
        let o = parse_up_output(stderr);
        assert_eq!(o.auth_url.as_deref(), Some("https://login.tailscale.com/a/5e6f7a8b9c"));
        assert!(!o.success);
        assert_eq!(o.error, None);

        let done = format!("{stderr}Success.\n");
        let o = parse_up_output(&done);
        assert!(o.success);
        assert_eq!(o.auth_url.as_deref(), Some("https://login.tailscale.com/a/5e6f7a8b9c"));
    }

    #[test]
    fn up_output_approve_and_errors() {
        let o = parse_up_output(
            "\nTo approve your machine, visit (as admin):\n\n\thttps://login.tailscale.com/admin/machines\n\n",
        );
        assert_eq!(o.approve_url.as_deref(), Some("https://login.tailscale.com/admin/machines"));
        assert_eq!(o.auth_url, None);

        let flags = "Error: changing settings via 'tailscale up' requires mentioning all\nnon-default flags. To proceed, either re-run your command with --reset or\nuse the command below to explicitly mention the current value of\nall non-default settings:\n\n\ttailscale up --accept-routes=false\n";
        let o = parse_up_output(flags);
        assert!(o.error.as_deref().unwrap().starts_with("Error: changing settings via 'tailscale up'"));
        assert!(!o.success);

        assert_eq!(parse_up_output("Success.\n"), UpOutput { success: true, ..Default::default() });
        assert_eq!(parse_up_output(""), UpOutput::default());
    }

    #[test]
    fn ownership_errors() {
        assert!(is_ownership_error("the target profile does not belong to the user"));
        assert!(is_ownership_error("Tailscale already in use by DESKTOP-01\\alex, pid 1234"));
        assert!(is_ownership_error("Access denied: watch IPN bus access denied"));
        assert!(is_ownership_error("Open: Access is denied."));
        assert!(!is_ownership_error("Tailscale was already stopped."));
        assert!(!is_ownership_error("Success."));
        assert!(!is_ownership_error("disconnect not allowed: always-on mode is enabled"));
    }

    #[test]
    fn meaningful_lines() {
        assert_eq!(
            first_meaningful_line("\n\n  the target profile does not belong to the user\n"),
            Some("the target profile does not belong to the user")
        );
        assert_eq!(first_meaningful_line("To authenticate, visit:\n\n\thttps://x\n"), None);
        assert_eq!(first_meaningful_line(""), None);
    }

    #[test]
    fn decisions() {
        assert_eq!(decide_up(None), UpDecision::RunUp);
        let running = parse_status_json(RUNNING).unwrap();
        assert_eq!(decide_up(Some(&running)), UpDecision::AlreadyConnected);
        let mut b = running.clone();
        b.state = "NeedsMachineAuth".into();
        assert_eq!(decide_up(Some(&b)), UpDecision::NeedsMachineAuth);
        b.state = "NoState".into();
        assert_eq!(decide_up(Some(&b)), UpDecision::RunUp);
    }

    fn installed(service: ServiceState) -> TailscaleStatus {
        TailscaleStatus {
            installed: true,
            exe_path: Some(PathBuf::from(r"C:\Program Files\Tailscale\tailscale.exe")),
            version: Some("1.104.6".into()),
            service,
            ..Default::default()
        }
    }

    #[test]
    fn stopped_service_is_plainly_disconnected() {
        // What down() reports at the end: no backend state (never a service label, which the UI
        // would render as an unknown 🟡 state), not connected, no error.
        let mut before = installed(ServiceState::Stopped);
        before.backend_state = Some("Running".into());
        before.connected = true;
        before.ipv4 = Some("100.101.102.103".into());
        before.health = vec!["x".into()];
        before.error = Some("stale".into());
        let st = without_daemon(before);
        assert_eq!(st.backend_state, None);
        assert!(!st.connected);
        assert_eq!((st.ipv4, st.ipv6, st.auth_url, st.error), (None, None, None, None));
        assert!(st.health.is_empty());
        assert_eq!(st.service, ServiceState::Stopped);
        assert!(st.installed && st.version.is_some() && st.exe_path.is_some());
    }

    #[test]
    fn daemon_states() {
        assert!(daemon_may_run(&ServiceState::Running));
        assert!(daemon_may_run(&ServiceState::Unknown));
        for s in [ServiceState::Stopped, ServiceState::StopPending, ServiceState::StartPending, ServiceState::Paused] {
            assert!(!daemon_may_run(&s), "{s:?}");
        }
        assert_eq!(state_text(&installed(ServiceState::Stopped)), "service stopped");
        assert_eq!(state_text(&installed(ServiceState::StartPending)), "service starting");
        assert_eq!(state_text(&installed(ServiceState::Running)), "unknown");
        let mut st = installed(ServiceState::Running);
        st.backend_state = Some(" NeedsLogin ".into());
        assert_eq!(state_text(&st), "NeedsLogin");
    }

    #[test]
    fn status_args_skip_the_peer_map() {
        assert_eq!(STATUS_ARGS, ["status", "--json", "--peers=false"]);
        assert_eq!(STATUS_ARGS_LEGACY, ["status", "--json"]);
        const { assert!(LEGACY_STATUS_CAPTURE_BYTES > process::MAX_CAPTURE_BYTES) };
    }

    #[test]
    fn detects_cli_without_peers_flag() {
        let old = "flag provided but not defined: -peers\nShow state of tailscaled and its connections\n\nUSAGE\n";
        assert!(peers_flag_unsupported(old));
        assert!(!peers_flag_unsupported("flag provided but not defined: -bogus"));
        assert!(!peers_flag_unsupported(RUNNING));
        assert!(!peers_flag_unsupported(""));
    }

    #[test]
    fn legacy_cli_is_remembered_by_path_and_version() {
        let fake = Path::new(r"C:\definitely\missing\tailscale-test-legacy.exe");
        let other = Path::new(r"C:\definitely\missing\tailscale-test-other.exe");
        remember_legacy_cli(fake);
        assert!(is_known_legacy_cli(fake));
        assert!(!is_known_legacy_cli(other));
        assert_eq!(cli_key(fake), format!("{}|", fake.display()));
        *LEGACY_CLI.lock().unwrap() = None;
        assert!(!is_known_legacy_cli(fake));
    }

    fn output(stdout: &str, stderr: &str, exit: Option<u32>, timed_out: bool) -> ProcessOutput {
        ProcessOutput { exit_code: exit, stdout: stdout.into(), stderr: stderr.into(), timed_out }
    }

    #[test]
    fn backend_from_outputs() {
        let ok = backend_from_output(&output(RUNNING, "", Some(0), false), process::MAX_CAPTURE_BYTES).unwrap();
        assert_eq!(ok.state, "Running");
        // Non-zero exit with valid JSON is still parsed.
        assert_eq!(backend_from_output(&output(STOPPED, "", Some(1), false), 1 << 20).unwrap().state, "Stopped");
        let t = backend_from_output(&output("", "", None, true), 1 << 20).unwrap_err();
        assert!(t.transient && t.msg.contains("timed out"), "{t:?}");
        let e = backend_from_output(
            &output("", "failed to connect to local tailscaled; it doesn't appear to be running", Some(1), false),
            1 << 20,
        )
        .unwrap_err();
        assert!(e.transient && e.msg.contains("failed to connect to local tailscaled"), "{e:?}");
        // Output that filled the capture buffer was cut off: say so instead of quoting JSON.
        let cut = &RUNNING[..RUNNING.len() / 2];
        let e = backend_from_output(&output(cut, "", Some(0), false), cut.len()).unwrap_err();
        assert!(e.msg.contains("was cut off"), "{e:?}");
        let e = backend_from_output(&output("", "", Some(0), false), 1 << 20).unwrap_err();
        assert!(e.msg.ends_with("no output"), "{e:?}");
    }

    #[test]
    fn parse_without_peers_output() {
        // Shape of `status --json --peers=false` (1.104.6, starting up): "Peer": null.
        let j = r#"{
  "Version": "1.104.6-t3b273a64c-gdf9d2ed85",
  "TUN": true,
  "BackendState": "NoState",
  "HaveNodeKey": true,
  "AuthURL": "",
  "TailscaleIPs": null,
  "Self": {"ID": "", "HostName": "DESKTOP-01", "TailscaleIPs": null, "Addrs": ["192.168.1.20:41641"], "Online": false},
  "Health": ["Tailscale is starting. Please wait."],
  "MagicDNSSuffix": "",
  "CurrentTailnet": null,
  "CertDomains": null,
  "Peer": null,
  "User": null,
  "ClientVersion": null
}
"#;
        let b = parse_status_json(j).unwrap();
        assert_eq!(b.state, "NoState");
        assert!(b.have_node_key && !b.has_tailnet && !b.online);
        assert_eq!(b.hostname.as_deref(), Some("DESKTOP-01"));
        assert_eq!((b.ipv4, b.ipv6), (None, None));
        assert_eq!(b.health, vec!["Tailscale is starting. Please wait.".to_string()]);
    }

    #[test]
    fn parse_is_lenient_about_field_types() {
        // A changed type loses only that field; the rest of the status survives.
        let j = r#"{"BackendState":"Running","HaveNodeKey":"yes","AuthURL":null,
            "TailscaleIPs":["100.64.0.9", 42, " fd7a::9 "],
            "Self":{"HostName":["x"],"TailscaleIPs":"100.64.0.1","Online":1},
            "Health":[{"Text":"structured"},"plain warning"],
            "CurrentTailnet":{"Name":7},"Peer":{"a":{"HostName":"phone"}}}"#;
        let b = parse_status_json(j).unwrap();
        assert_eq!(b.state, "Running");
        assert!(!b.have_node_key && !b.online);
        assert_eq!(b.auth_url, None);
        assert_eq!(b.hostname, None);
        // Self.TailscaleIPs unusable → top-level list; the non-string element is dropped.
        assert_eq!(b.ipv4.as_deref(), Some("100.64.0.9"));
        assert_eq!(b.ipv6.as_deref(), Some("fd7a::9"));
        assert_eq!(b.health, vec!["plain warning".to_string()]);
        assert!(b.has_tailnet);
        assert_eq!(b.tailnet, None);
    }

    #[test]
    fn parse_picks_the_status_object_among_noise() {
        // Text with braces before the object and trailing text with braces after it.
        let noisy = format!("warning: config {{legacy}} ignored\n{RUNNING}\nnote: done {{ok}}\n");
        assert_eq!(parse_status_json(&noisy).unwrap().state, "Running");
        let first_line_json = format!("{{\"Other\":1}}\n{STOPPED}");
        assert_eq!(parse_status_json(&first_line_json).unwrap().state, "Stopped");
        // An object without BackendState is still accepted when nothing better exists.
        assert_eq!(
            parse_status_json(r#"{"Self":{"HostName":"DESKTOP-01"}}"#).unwrap().hostname.as_deref(),
            Some("DESKTOP-01")
        );
        assert!(json_candidates(&"{\n".repeat(50)).len() <= MAX_JSON_CANDIDATES + 1);
        assert_eq!(json_candidates("  {\"a\":1}"), vec![2]);
        assert_eq!(json_candidates("x {"), vec![2]);
        assert!(json_candidates("no json").is_empty());
    }

    #[test]
    fn versions_and_dirs() {
        assert_eq!(format_version((1 << 16) | 104, 6 << 16), "1.104.6");
        assert_eq!(format_version((2 << 16) | 3, (4 << 16) | 5), "2.3.4.5");
        assert_eq!(
            dir_from_reg_value(r"C:\Program Files\Tailscale\"),
            Some(PathBuf::from(r"C:\Program Files\Tailscale"))
        );
        assert_eq!(dir_from_reg_value(r#""D:\Apps\TS""#), Some(PathBuf::from(r"D:\Apps\TS")));
        assert_eq!(dir_from_reg_value(r"E:\"), Some(PathBuf::from(r"E:\")));
        assert_eq!(dir_from_reg_value("  "), None);
        assert_eq!(cli_in_dir(Path::new(r"relative\dir")), None);
    }

    #[test]
    fn steps_prefixes() {
        let mut s = Steps::default();
        s.ok("a");
        s.info("i");
        s.warn("b");
        s.fail("c");
        assert_eq!(s.0, vec!["✅ a", "ℹ️ i", "⚠️ b", "❌ c"]);
    }

    fn user_session(id: u32, user: &str) -> SessionInfo {
        SessionInfo { id, user: user.into(), state: "Active".into(), station: "Console".into(), ..Default::default() }
    }

    #[test]
    fn app_launch_plan() {
        // Already running somewhere: never started a second time (the user is not even looked up).
        assert_eq!(plan_app(true, Some(user_session(1, "alex"))), AppPlan::AlreadyRunning);
        assert_eq!(plan_app(true, None), AppPlan::AlreadyRunning);
        assert_eq!(
            plan_app(false, Some(user_session(3, "alex"))),
            AppPlan::Launch { session_id: 3, user: "alex".into() }
        );
        assert_eq!(plan_app(false, None), AppPlan::NoUser);
    }

    #[test]
    fn app_launch_steps_without_starting_anything() {
        // A CLI path without a tailscale-ipn.exe next to it: nothing can be (or is) started.
        let fake_cli = Path::new(r"C:\definitely\missing\Tailscale\tailscale.exe");
        assert_eq!(app_path(fake_cli), None);
        let run = |plan: AppPlan| {
            let mut s = Steps::default();
            let started = start_app(fake_cli, &plan, &mut s);
            (started, s.0)
        };
        assert_eq!(run(AppPlan::AlreadyRunning), (false, vec!["✅ Tailscale app is already running".to_string()]));
        assert_eq!(
            run(AppPlan::NoUser),
            (false, vec!["ℹ️ No user is logged in — relying on Tailscale Unattended mode".to_string()])
        );
        let (started, steps) = run(AppPlan::Launch { session_id: 1, user: "alex".into() });
        assert!(!started);
        assert_eq!(
            steps,
            vec!["⚠️ The Tailscale app (tailscale-ipn.exe) was not found next to tailscale.exe — not started"]
        );
    }

    #[test]
    fn readiness_after_starting_the_service_or_app() {
        let b = |json: &str| -> BackendResult { Ok(parse_status_json(json).unwrap()) };
        let err = |transient| -> BackendResult { Err(QueryError { msg: "x".into(), transient }) };
        for connecting in [false, true] {
            assert!(!backend_ready(&b(NO_STATE), connecting));
            assert!(!backend_ready(&b(r#"{"BackendState":"Starting"}"#), connecting));
            assert!(!backend_ready(&err(true), connecting));
            assert!(backend_ready(&err(false), connecting));
            assert!(backend_ready(&b(RUNNING), connecting));
            assert!(backend_ready(&b(STOPPED), connecting));
            // Logged out but a profile exists: `up` can handle it.
            let with_profile = NEEDS_LOGIN.replace(r#""CurrentTailnet":null"#, r#""CurrentTailnet":{"Name":"t"}"#);
            assert!(backend_ready(&b(&with_profile), connecting));
        }
        // No profile: tailscaled's placeholder until the app's user profile loads.
        assert!(!backend_ready(&b(NEEDS_LOGIN), true));
        assert!(backend_ready(&b(NEEDS_LOGIN), false));
    }

    #[test]
    fn still_starting_hints() {
        let launch = AppPlan::Launch { session_id: 1, user: "alex".into() };
        assert_eq!(
            still_starting_text("NoState", &AppPlan::NoUser, false),
            "Tailscale is still starting after 30 s (state: NoState) — nobody is logged in to Windows, so only \
             Run unattended can connect it"
        );
        assert_eq!(
            still_starting_text("NoState", &launch, false),
            "Tailscale is still starting after 30 s (state: NoState) — the Tailscale app is not running"
        );
        assert_eq!(
            still_starting_text(" Starting ", &AppPlan::AlreadyRunning, true),
            "Tailscale is still starting after 30 s (state: Starting)"
        );
        assert_eq!(still_starting_text("", &launch, true), "Tailscale is still starting after 30 s (state: unknown)");
    }

    #[test]
    fn installed_app_image_check() {
        let dir = Path::new(r"C:\Program Files\Tailscale");
        for image in [
            r"C:\Program Files\Tailscale\tailscale-ipn.exe",
            r"c:\program files\tailscale\TAILSCALE-IPN.EXE",
            r"\\?\C:\Program Files\Tailscale\tailscale-ipn.exe",
            r"C:/Program Files/Tailscale/tailscale-ipn.exe",
        ] {
            assert!(is_installed_app(Path::new(image), dir), "{image}");
        }
        assert!(is_installed_app(
            Path::new(r"C:\Program Files\Tailscale\tailscale-ipn.exe"),
            Path::new(r"C:\Program Files\Tailscale\")
        ));
        for image in [
            r"C:\Users\alex\Downloads\tailscale-ipn.exe",
            r"C:\Program Files\Tailscale\sub\tailscale-ipn.exe",
            r"C:\Program Files\tailscale-ipn.exe",
            r"C:\Program Files\Tailscale\tailscale.exe",
            r"C:\Program Files\Tailscale\tailscaled.exe",
            r"C:\Program Files\Tailscale2\tailscale-ipn.exe",
            r"tailscale-ipn.exe",
            "",
        ] {
            assert!(!is_installed_app(Path::new(image), dir), "{image}");
        }
        // The install folder itself must be a real absolute folder.
        assert!(!is_installed_app(Path::new(r"Tailscale\tailscale-ipn.exe"), Path::new("Tailscale")));
        assert!(!is_installed_app(Path::new(r"\tailscale-ipn.exe"), Path::new("")));
        assert_eq!(dir_key(Path::new(r"\\?\C:\Program Files\Tailscale\")), r"c:\program files\tailscale");
    }

    /// Different spellings of the same existing folder (a `..` detour, an 8.3 short name when the
    /// volume has them) still match; a different existing folder does not.
    #[test]
    fn installed_app_check_compares_final_paths() {
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

        let root = std::env::temp_dir().join(format!("predator-ts-canonical-test-{}", std::process::id()));
        let install = root.join("Tailscale Install Folder");
        let other = root.join("Other Folder");
        std::fs::create_dir_all(install.join("sub")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let image = install.join(APP_EXE);
        std::fs::write(&image, b"").unwrap();
        std::fs::write(other.join(APP_EXE), b"").unwrap();

        assert!(is_installed_app(&image, &install));
        assert!(is_installed_app(&image, &install.join("sub").join("..")), "a `..` detour is the same folder");
        assert!(!is_installed_app(&image, &other));
        assert!(!is_installed_app(&other.join(APP_EXE), &install));
        assert!(!is_installed_app(&install.join("sub").join(APP_EXE), &install), "missing file never matches");
        assert!(!is_installed_app(&install.join("missing").join("..").join(APP_EXE), &other));

        // 8.3 short name of the install folder (only when the volume generates short names).
        let long = wide_path(&install);
        let mut buf = vec![0u16; 1024];
        let n = unsafe { GetShortPathNameW(long.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n > 0 && n < buf.len() {
            let short = PathBuf::from(OsString::from_wide(&buf[..n]));
            if dir_key(&short) != dir_key(&install) {
                assert!(!same_app_path(&image, &short), "the spellings differ textually");
                assert!(is_installed_app(&image, &short), "{} vs {}", image.display(), short.display());
                assert!(is_installed_app(&short.join(APP_EXE), &install));
                assert!(!is_installed_app(&short.join(APP_EXE), &other));
            } else {
                println!("no 8.3 name for {} on this volume", install.display());
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn app_close_steps() {
        let run = |results: &[(u32, AppKill)], still: &[u32]| {
            let mut s = Steps::default();
            report_app_close(results, still, &mut s);
            s.0
        };
        assert_eq!(run(&[], &[]), vec!["✅ Tailscale app is not running"]);
        assert_eq!(run(&[(10, AppKill::Terminated)], &[]), vec!["✅ Tailscale app closed"]);
        assert_eq!(run(&[(10, AppKill::Terminated), (11, AppKill::Gone)], &[]), vec!["✅ Tailscale app closed"]);
        assert_eq!(
            run(&[(10, AppKill::Terminated), (12, AppKill::Foreign(r"D:\x\tailscale-ipn.exe".into()))], &[12]),
            vec![
                r"⚠️ Left tailscale-ipn.exe alone — not the installed Tailscale app (PID 12: D:\x\tailscale-ipn.exe)",
                "❌ The Tailscale app is still running (PID 12)",
            ]
        );
        assert_eq!(
            run(&[(10, AppKill::Failed("Access is denied".into()))], &[10]),
            vec![
                "❌ Could not close the Tailscale app: PID 10: Access is denied",
                "❌ The Tailscale app is still running (PID 10)",
            ]
        );
        // A new instance appeared after the snapshot: still reported.
        assert_eq!(run(&[], &[42]), vec!["❌ The Tailscale app is still running (PID 42)"]);
    }

    #[test]
    fn down_outcomes() {
        let stopped = ServiceState::Stopped;
        assert_eq!(down_outcome(&stopped, None, &[], false, &[]), Ok(()));
        assert_eq!(
            down_outcome(&stopped, None, &[], true, &[7, 8]),
            Err("The Tailscale app (tailscale-ipn.exe) is still running (PID 7, 8)".into())
        );
        assert_eq!(
            down_outcome(&stopped, None, &[], true, &[]),
            Err("The Tailscale app (tailscale-ipn.exe) is still running".into())
        );
        assert_eq!(
            down_outcome(&stopped, None, &[5], false, &[]),
            Err("tailscaled.exe is still running (PID 5)".into())
        );
        assert_eq!(down_outcome(&ServiceState::Running, Some("boom".into()), &[5], true, &[7]), Err("boom".into()));
        assert_eq!(
            down_outcome(&ServiceState::StopPending, None, &[], true, &[7]),
            Err("The Tailscale service is Stopping".into())
        );
    }

    #[test]
    fn app_connecting_rule() {
        // (app_started, service_started, app_was_running)
        assert!(app_is_connecting(true, false, false));
        assert!(app_is_connecting(true, true, false));
        assert!(app_is_connecting(false, true, true), "a running app reconnects to a fresh service");
        assert!(!app_is_connecting(false, false, true), "running app + running service: nothing pending");
        assert!(!app_is_connecting(false, true, false), "no app to wait for");
        assert!(!app_is_connecting(false, false, false));
    }

    #[test]
    fn app_path_and_status_field() {
        assert_eq!(app_path(Path::new("tailscale.exe")), None);
        // Read-only process snapshots. Another test may start/stop a stand-in tailscale-ipn.exe
        // meanwhile, so only compare when the snapshots around the call agree.
        let before = !process::find_processes(APP_EXE).is_empty();
        let running = app_is_running();
        let after = !process::find_processes(APP_EXE).is_empty();
        if before == after {
            assert_eq!(running, before);
        }
        let st = without_daemon(TailscaleStatus { app_running: true, ..installed(ServiceState::Stopped) });
        assert!(st.app_running, "the app state survives a stopped daemon");
        if let Some(cli) = find_cli() {
            // Read-only: the installed app next to the CLI (never started here).
            if let Some(app) = app_path(&cli) {
                assert!(is_installed_app(&app, cli.parent().unwrap()), "{}", app.display());
            }
        }
    }

    #[test]
    fn image_path_of_own_process() {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: pseudo handle of this process.
        let image = process_image_path(unsafe { GetCurrentProcess() }).unwrap();
        let me = std::env::current_exe().unwrap();
        assert_eq!(dir_key(&image), dir_key(&me), "{} vs {}", image.display(), me.display());
    }

    /// The terminate path on a stand-in: a copy of PING.EXE named tailscale-ipn.exe in a private
    /// temp folder (never a real Tailscale process).
    #[test]
    fn terminate_app_checks_the_image_before_killing() {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        let soon = || Instant::now() + Duration::from_secs(5);
        assert!(matches!(terminate_app(0, Path::new(r"C:\x"), soon()), AppKill::Failed(_)));
        assert!(matches!(terminate_app(4, Path::new(r"C:\x"), soon()), AppKill::Failed(_)));
        assert_eq!(terminate_app(0xFFFF_FFF0, Path::new(r"C:\x"), soon()), AppKill::Gone);

        let sysroot = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        let ping = sysroot.join("System32").join("PING.EXE");
        let dir = std::env::temp_dir().join(format!("predator-ts-app-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stand_in = dir.join(APP_EXE);
        std::fs::copy(&ping, &stand_in).unwrap();
        let spawn = |exe: &Path| {
            let _lock = process::spawn_lock();
            std::process::Command::new(exe)
                .args(["-n", "30", "127.0.0.1"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };

        // Same name, wrong folder → left alone.
        let mut child = spawn(&stand_in);
        let elsewhere = Path::new(r"C:\Program Files\Tailscale");
        match terminate_app(child.id(), elsewhere, soon()) {
            AppKill::Foreign(path) => assert!(path.to_ascii_lowercase().ends_with(r"\tailscale-ipn.exe"), "{path}"),
            other => panic!("{other:?}"),
        }
        assert!(child.try_wait().unwrap().is_none(), "a foreign tailscale-ipn.exe must not be terminated");
        // Right folder → terminated, and terminate_app returns only once it has exited.
        assert_eq!(terminate_app(child.id(), &dir, soon()), AppKill::Terminated);
        assert_eq!(
            child.try_wait().unwrap().and_then(|s| s.code()),
            Some(APP_KILLED_EXIT_CODE as i32),
            "terminate_app returned before the process had exited"
        );

        // Right folder, wrong program name → left alone.
        let mut ping_child = spawn(&ping);
        assert!(matches!(terminate_app(ping_child.id(), ping.parent().unwrap(), soon()), AppKill::Foreign(_)));
        assert!(ping_child.try_wait().unwrap().is_none());
        let _ = ping_child.kill();
        let _ = ping_child.wait();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Read-only: registry/SCM/file lookups and the version resource. Never runs the CLI.
    #[test]
    fn live_find_cli_and_version() {
        match find_cli() {
            Some(p) => {
                assert!(p.is_file() && p.ends_with(CLI_EXE), "{}", p.display());
                let v = file_version(&p).expect("version resource");
                assert!(v.split('.').count() >= 3 && v.split('.').all(|x| x.parse::<u32>().is_ok()), "{v}");
                println!("tailscale cli = {} version = {v}", p.display());
            }
            None => println!("Tailscale is not installed on this machine"),
        }
        assert_eq!(file_version(Path::new(r"C:\definitely\missing\file.exe")), None);
    }
}
