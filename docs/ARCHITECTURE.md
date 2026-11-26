# Vigil — Architecture

This document describes how Vigil 1.0.0 is built: processes and threads,
data files, multi-user authorization and pairing, the Telegram protocol, the single-file setup,
the event-log monitor, the HTTPS transport, the security model and the techniques that keep the
idle footprint small. User-facing instructions are in the [README](../README.md),
[docs/TELEGRAM_SETUP.md](TELEGRAM_SETUP.md) and [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md);
the short security policy is in [SECURITY.md](../SECURITY.md). References such as §7 point to
sections of this document.

## Contents

1. [Product summary](#1-product-summary)
2. [Process and thread model (service)](#2-process-and-thread-model-service)
3. [Data and files](#3-data-and-files)
4. [Module map](#4-module-map)
5. [Coding rules](#5-coding-rules)
6. [Users, roles and pairing](#6-users-roles-and-pairing)
7. [Telegram UI specification](#7-telegram-ui-specification)
8. [Service runtime](#8-service-runtime)
9. [Single-file release and setup](#9-single-file-release-and-setup)
10. [Tray](#10-tray)
11. [Login monitor (event log)](#11-login-monitor-event-log)
12. [Chat auto-clean](#12-chat-auto-clean)
13. [Tailscale management](#13-tailscale-management)
14. [Logging and flood protection](#14-logging-and-flood-protection)
15. [Platform facts](#15-platform-facts)
16. [HTTPS transport](#16-https-transport)
17. [Resource footprint](#17-resource-footprint)
18. [Assets and build](#18-assets-and-build)
19. [Security review](#19-security-review)

## 1. Product summary

A Windows 10/11 x64 background service (`predator-service.exe`, service name
`PredatorRemoteController`, runs as **LocalSystem**, automatic start at boot, before any user
signs in) that:

* monitors Windows logons (Security log 4624/4625/4634/4647/4778/4779, plus 4719 audit-policy
  changes and 1102 log cleared) and OpenSSH logons (`OpenSSH/Operational`, plus `OpenSSH/Admin`
  for MaxAuthTries) and sends Telegram alerts to **every paired Telegram account** (at most 20,
  roles Admin and User, §6);
* is controlled from Telegram (private chats only, authorization by numeric user id) with an
  inline-keyboard UI: status, network, battery, login history, feature toggles,
  shutdown/restart/sleep/hibernate (confirmation required), lock/logout (no confirmation),
  Tailscale status/up/down (including the Tailscale app, §13), the list of paired accounts;
* adds Telegram accounts through a one-time **pairing code** created on the PC itself (tray,
  setup menu or command line, §6) — or, for an administrator on the PC, by numeric id
  (`setup --telegram-id`, `set-owner`);
* keeps the chats tidy: login, logout, failed-login, SSH and security alerts stay; menus,
  replies, status notices and the users' own commands are deleted automatically, or at once with
  `/clear` (§12);
* queues notifications on disk while offline and delivers them (with original timestamps) when
  the internet returns, to every user who does not have them yet;
* has a separate per-user tray app (`predator-tray.exe`) that talks to the service over a secured
  named pipe and never duplicates monitoring or Telegram;
* is released as one file, `Vigil.exe` (the service executable with the tray
  embedded), which installs, updates and uninstalls itself (§9).

**Top priorities: extremely low RAM, ~zero idle CPU, reliability, security.**
No async runtime (no tokio). Native Win32 via `windows-sys` 0.61 (+ `windows` 0.62 *only* for the
WinRT/NLM Wi-Fi SSID lookup, which runs in the `ssid-helper` child process, never in the service).
`schannel` 0.1.30 (thin SChannel bindings on the same `windows-sys` 0.61) for the direct HTTPS
transport (§16). `serde`/`serde_json` for JSON. Nothing else at runtime.

`build.rs` delay-loads, for `predator-service` only, the DLLs that are needed on demand:
`winhttp` (HTTPS proxy fallback only, §16), `ole32`, `oleaut32`, `combase`,
`api-ms-win-core-winrt-l1-1-0`, `wlanapi` (SSID helper only), `powrprof` (power), `version`
(Tailscale CLI version), `userenv` (processes in a user session), `wtsapi32` (session queries)
and `shell32` (only the interactive setup's elevation prompt). DLLs on the idle path
(`kernel32`, `advapi32`, `wevtapi`, `iphlpapi`, `ntdll`, and for the direct HTTPS transport
`ws2_32`, `secur32` and `crypt32`) stay static imports; a unit test in `build.rs` pins both
lists (§18).

## 2. Process and thread model (service)

```
SCM dispatcher thread ── control handler (fast: copies control codes into a channel)
main service thread  ── orchestrator: startup (EcoQoS on), waits for stop/preshutdown, shutdown
                        sequence (EcoQoS off)
telegram-poller      ── blocking getUpdates through net::http::HttpClient (§16; 50 s long poll,
                        cut short by Shared::interrupt_long_poll on a connectivity change or
                        resume; timeout 0 while catching up on a backlog) →
                        Bot::handle_update_with(update, from_backlog) → chat sweep of every
                        user's chat (janitor, §12) after every successful cycle → memory-trim
                        check after a cycle without updates (§17)
notify-sender        ── waits on ctx.sender_wake; delivers queue items in order to every paired
                        user; backoff on failure; flushes coalesced queue writes before every
                        wait (§17)
monitor              ── WaitForMultipleObjects([ctx.stop, own stop, settings-changed,
                        security-signal, ssh-signal, ssh-admin-signal], next deadline or
                        INFINITE) → drain ONLY the signalled channels (EvtNext, 32 per batch,
                        1000 ms) → ctx.emit_event (§11)
ipc-server           ── ConnectNamedPipe loop; reads one request (≤ 4 KiB, 1.5 s timeout) and
                        answers quick requests (status, feature switch, settings reload,
                        pairing, user list) on this thread
ipc-worker (≤ 2)     ── TailscaleStatus / RestartService for authorized callers only
(OS thread pool)     ── NotifyNetworkConnectivityHintChange callback → Shared::connectivity_changed
(short-lived)        ── Tailscale up/down worker, sleep/hibernate worker, child-process pipe
                        readers, offline-send helper (stop only)
(no HTTP threads)    ── the direct HTTPS transport runs on the calling thread; WinHTTP's worker
                        pool exists only after the client was routed to WinHTTP (§16)
```
Idle = every thread blocked in the kernel. Apart from the 50 s long poll, no periodic timer fires
more often than once a minute: monitor watchdog (EventLog PID, sshd_config while SSH monitoring is
on) every 5 min, audit-policy re-check every 10 min, bookmark refresh hourly — and none of them
while both monitors are off. One-shot deadlines (subscription retry, stalled-queue retry after 60 s,
a held console disconnect, the failed-login summary, the coalesced history write) only follow an
event, and the monitor never waits less than 1 s. The working-set trim (§17) has no timer: it is
decided at quiet points of the poller loop. The only exception is the start-up trim without a
usable token, for which the poller's idle wait ends once at the trim's due time. Pairing codes
(§6) live in memory and need no timer: an expired code is detected when it is used or queried.

Child processes of the service (all created under `sys::process::SPAWN_LOCK`, never through a
shell, fixed arguments): `tailscale.exe status --json --peers=false | up | down` (plain
`status --json` only for a CLI without `--peers`), `predator-tray.exe --lock` in a user session,
`predator-service.exe ssid-helper` (8 s timeout), the detached `predator-service.exe
restart-helper --data-dir <root>`, and the Tailscale app `tailscale-ipn.exe` (no arguments),
started by `/tailscale up` in the active user's session with `session::launch_in_session` (no job,
no wait, user environment; it keeps running on its own, §13). The interactive setup is a separate
elevated console process, not the service; what it starts is listed in §9.

Stopping: the orchestrator switches EcoQoS off (the stop has a hard time budget), sets
`ctx.stop`, queues the "going offline" message durably and delivers it to every paired user on an
`offline-send` helper thread (3 s time limit per phase; it can reuse an idle kept-alive connection
of the pool) while the monitors stop (`Monitors::stop` also queues a pending failed-login summary
and writes `history.json`). The transport is deliberately **not** interrupted at stop: nothing
waits for the long poll (the process exits), and an interrupt would cancel an alert being
delivered and close the idle connection the offline send can reuse. A connectivity change during
the stop does not interrupt either. The stop waits for the send at most `OFFLINE_SEND_BUDGET` =
3 s, measured from the start of the stop, reporting an SCM checkpoint at least once a second
(STOP_PENDING wait hint 8 s); recipients reached are recorded in the queue item, and anyone not
reached gets the notice after the next start. Then the coalesced queue writes are flushed
(`NotificationQueue::flush`), `SERVICE_STOPPED` is reported and the process exits. Threads
blocked in a long poll are not joined; all other persistent state is written atomically as it
changes, so nothing is lost. The last processed Telegram `update_id` is persisted together with
the bot id (`telegram-state.json`) *before* the update is dispatched, so a command is never
executed twice after a restart.

## 3. Data and files

Data directory `%ProgramData%\Predator`. ACL: owner Administrators, protected DACL
`O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (`paths::DATA_DIR_SDDL`) — SYSTEM + Administrators
only, inherited by everything inside. See §19 for when an existing folder is trusted.

| file | owner module | content |
|---|---|---|
| settings.json | config.rs | `authorized_users` (id, display name, role, added time), `owner_windows_sid` (tray owner), `bot_username`, feature switches, options (`dry_run`, `stale_command_secs`, `confirm_timeout_secs`, `lifecycle_notifications`, `auto_clean_chat`, `chat_clean_after_secs`) |
| token.dat | secrets.rs | DPAPI-protected bot token (`PDT1` + scope byte `M`/`U` + blob); always written in machine scope |
| queue.json | notify/queue.rs | pending outgoing notifications (≤ 1000), each with `delivered_to` (the recipients that have it); pushes written before they return, acks and delivery marks coalesced (≤ 1 write per 2 s, §17) |
| history.json | notify/history.rs | last 50 login events (with dedupe keys); writes coalesced to ≤ 1 per 5 s |
| telegram-state.json | service/poller.rs | `last_update_id`, `updated_unix`, `bot_id` (written by the poller and by the command line's direct pairing; a file without `bot_id` is adopted by the next poller start) |
| chat-cleanup.json | telegram/janitor.rs | chat auto-clean list `{version, bot_id, entries:[{chat_id, message_id, sent_unix, active_unix}]}`, ≤ 500 entries, no message text (§12) |
| bookmarks/security.xml, bookmarks/openssh.xml, bookmarks/openssh-admin.xml | monitor | event-log bookmarks (one subscription per channel) |
| audit-backup.json | monitor/audit.rs | original audit policy (restored on uninstall; deleted only after a verified restore) |
| logs/predator.log | logging.rs | rotated at 1 MiB, 1 backup, tokens redacted, flood guard (§14) |
| logs/security.log | logging.rs | rotated at 1 MiB, 3 backups (`security.log.1` … `.3`), tokens redacted |
| DRY_RUN (marker) | service | presence = simulate power/lock/logout/Tailscale up+down (read at start) |

Pairing codes are never written to disk (§6).

All state files are written through `paths::atomic_write` (temp file + rename). `SettingsStore`
remembers the identity of `settings.json` (volume serial, file id, size, last-write time) and
re-reads the file before applying an update when another process changed it, so a stale in-memory
copy never overwrites a change made by the command line or setup (for example a removed account).
A corrupt `settings.json` or `queue.json` is renamed to `*.json.corrupt` and defaults are used.

An untrusted existing data folder is renamed to `Vigil.untrusted-YYYYMMDD-HHMMSS` by setup /
`install` and never read.

Program files: `<ProgramFilesDir>\Predator` (read from
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion`, default `C:\Program Files\Predator`) with
`predator-service.exe` and `predator-tray.exe` (§9). Tray autostart: the HKLM Run value
`PredatorTray`.

## 4. Module map

| Module | Responsibility |
|---|---|
| `config` | `Settings`, `SettingsStore` (atomic writes, change listeners, re-read when another process replaced the file), `AuthorizedUser`, `UserRole`, `MAX_AUTHORIZED_USERS` |
| `pairing` | `PairingSlot`: the single active one-time pairing code and its brute-force limits |
| `features` | the nine feature switches (`Feature`, `FeatureSet`) |
| `context` | `AppContext` shared by every service thread; `emit_event`, `emit_system`, `emit_security`, `emit_notice` |
| `notify` | `EventDetails`, `Notification`, the persistent queue (`queue.rs`), the login history (`history.rs`), Telegram-HTML rendering (`format.rs`) |
| `monitor` | event-log subscriptions and their supervisor (`mod.rs`, `eventlog.rs`), classification (`logon.rs`, `ssh.rs`, `xml.rs`), audit policy (`audit.rs`) |
| `telegram` | Bot API client (`api.rs`), types, UI builders (`ui.rs`), dispatcher (`bot.rs`), chat janitor (`janitor.rs`) |
| `net` | HTTPS facade (`http.rs`), direct SChannel client (`direct.rs`, `http1.rs`), transport decision (`proxy.rs`), WinHTTP fallback (`winhttp.rs`), connectivity hints (`connectivity.rs`) |
| `sys` | allowlisted system operations behind `SystemActions`: power, sessions, network, battery, Tailscale, SCM queries, process spawning, privileges |
| `ipc` | named-pipe protocol (`IpcRequest`, `IpcResponse`) and client (`request`, `request_to_pid`) |
| `secrets` | DPAPI token storage |
| `paths`, `logging`, `util` | data paths and atomic writes, the logger, small helpers (signals, stop flag, backoff, time, randomness, Win32 handles) |
| `service` | `main_entry`: SCM plumbing (`scm.rs`), runtime threads (`runtime.rs`, `poller.rs`, `sender.rs`, `ipc_server.rs`, `pipe.rs`, `slot.rs`), command line (`cli.rs`, `commands.rs`, `pairing.rs`, `install.rs`, `selftest.rs`, `console.rs`), Windows security helpers (`winsec.rs`), interactive setup (`setup/`) |
| `tray` | the tray app: Win32 part (`ui.rs`), pure decisions (`model.rs`), SCM notifications (`watch.rs`) |

Binaries: `src/bin/predator-service.rs` calls `service::main_entry`, `src/bin/predator-tray.rs`
calls `tray::main_entry`.

Invariants that the rest of the code relies on:

* Monitors report events **only** via `ctx.emit_event(details, dedupe_key)`, which applies feature
  gating, history, rate limiting, rendering and durable queueing. If it returns `Err`, the
  bookmark must not advance. Dedupe keys are `<channel>:<EventRecordID>:<TimeCreated FILETIME>`.
* `Bot::handle_update(u)` == `Bot::handle_update_with(u, false)`.
* The IPC protocol only ever gains variants and optional fields (`ServiceStatusInfo.transport`
  has a serde default), so tray, command line and service of different builds understand each
  other; an unknown request is answered with `Error`, and required fields are never defaulted
  (a `start_pairing` without `admin` is refused rather than read as anything).
* `net::winhttp::{HttpClient, HttpError, HttpResponse}` re-exports the facade types of `net::http`.
* `secrets::migrate_to_user_scope` exists for completeness and is not called anywhere.

## 5. Coding rules

* Edition 2024; the code uses `let` chains, so Rust 1.88 or newer is required (`Cargo.toml`
  declares `rust-version = "1.88"`). `unsafe_op_in_unsafe_fn` is on: wrap unsafe calls inside
  `unsafe fn` in `unsafe {}`. Add a short `// SAFETY:` comment for non-obvious unsafe blocks.
* Must pass: `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --all-targets` (`scripts/build.ps1` runs all of them, §18).
* No `unwrap()`/`expect()` on fallible runtime paths (tests are fine). Never panic across FFI:
  wrap every `extern "system"` callback body in `std::panic::catch_unwind`.
* Thread entry points wrap their loop in `catch_unwind` and log + restart/continue — one failing
  feature must never take down the service.
* Never log the bot token, a pairing code or full Telegram URLs. HTTPS transport errors are built
  from error codes (system message table) or error kinds plus fixed text only
  (`net::http::io_error`), never from the host, the path or an `io::Error`'s own text. Never log
  details of other Telegram accounts beyond id/username/display name (≤ 64 chars) and the first
  64 chars of their text (with any pairing code hidden). Lines caused by unauthenticated parties
  go through `logging::security_untrusted(source, msg)` (rate-limited per source and globally).
* Never execute shell/PowerShell/CMD or any program path derived from Telegram input. The only
  child processes of the service: the discovered `tailscale.exe` (fixed argument lists:
  `status --json --peers=false`, legacy `status --json`, bare `up`, bare `down`), the Tailscale
  app `tailscale-ipn.exe` next to it (no arguments, `session::launch_in_session` only), our own
  `predator-tray.exe --lock`, our own `predator-service.exe ssid-helper` and our own
  `predator-service.exe restart-helper`. Every spawn holds `sys::process::SPAWN_LOCK`; handles are
  only made inheritable while that lock is held. The only foreign processes ever terminated are
  `tailscale-ipn.exe` instances whose image lies in the Tailscale install folder and
  `tailscaled.exe` instances that outlive the stopped `Tailscale` service (§13); setup terminates
  only `predator-tray.exe` processes whose image is exactly the installed tray (§9).
* Operational log lines go through the flood guard (§14); do not add your own throttling for
  ordinary log lines, but never log inside a tight loop either.
* Keep allocations modest; prefer stack buffers; free every Win32 allocation; close every handle
  (use `util::win::OwnedHandle`).
* Log with the `log_*!` macros: they check the level before formatting, so a suppressed line costs
  nothing. Do not build a log `String` yourself before calling them.
* No periodic timers for housekeeping (memory trims, flushes, cache clean-ups): hang them on a
  point the code reaches anyway (§17).
* Pure logic (parsing/classification/formatting/authorization/dialogs) must be unit-tested. The
  setup dialogs are written against small traits (`Io`, `WizardEnv`, `MenuEnv`) for that reason.
* windows-sys 0.61 types: `HANDLE = *mut c_void`, `BOOL = i32`, many `BOOLEAN` params are `bool`,
  `HINTERNET = *mut c_void`, `EVT_HANDLE = isize`. Check docs.rs when unsure.
* A missing windows-sys/windows feature goes into `Cargo.toml`. A new DLL import that is not
  needed at service start belongs in `DELAY_LOAD_DLLS` in `build.rs`.

## 6. Users, roles and pairing

### Authorized users (`config.rs`)
* `settings.authorized_users` is a list of `AuthorizedUser { id, name, role, added_unix }`, at
  most `MAX_AUTHORIZED_USERS` = 20. Authorization uses the numeric Telegram user id only
  (`Settings::is_authorized`: id > 0 and in the list). `name` is for display: `@username` or the
  first name, cleaned by `clean_user_name` (control characters become spaces, bidirectional-text
  controls are removed, at most 64 characters); `label()` falls back to `user <id>`.
* Roles (`UserRole`): **User** — every command and button (status, power, lock/logout, Tailscale,
  feature switches, the user list). **Admin** — the same, plus removing other accounts from
  Telegram (`/users`). The first account added to an empty list always becomes an Admin
  (`SettingsStore::add_user`), so somebody can always manage the list.
* `SettingsStore::remove_user` refuses unknown ids and the **last Admin** (`LAST_ADMIN_ERROR`:
  "The last admin cannot be removed (pair another admin first)."). Accounts with the role User can
  always be removed.
* `primary_user_id()` = the first Admin, else the first account; used where "somebody is paired"
  matters (sender, console input injection, status output).
* After every mutation `Settings::clean` keeps ids > 0, drops duplicates (the first entry wins),
  re-cleans names and truncates the list to 20.
* Migration: a `settings.json` in the single-owner format (field `owner_telegram_id`, no
  `authorized_users`) is migrated on load into `[{id, name: "owner", role: admin, added_unix: 0}]`.
  The field is never written again (`skip_serializing`); in memory it mirrors `primary_user_id()`.
  A mutation inside `SettingsStore::update` that assigns it keeps the single-owner meaning —
  `Some(id)` makes that account the only (Admin) user, `None` empties the list — which is how
  `set-owner --telegram-id ID` revokes every other account in one step. A mutation that changes
  `authorized_users` itself always wins over the deprecated field.
* The bot reads the list for every update, so a removed account loses access with its next update.
  A change made by the command line while the service runs reaches it through `ReloadSettings`
  (§8) or the re-read before the service's next write.

### Pairing codes (`pairing.rs`)
* One active code per service (`PairingSlot`, in memory only — a service restart cancels it).
  `start(role, ttl, created_by, now)` creates 8 random digits (`util::rand::digits`, rejection
  sampled from `BCryptGenRandom`), clamps the lifetime to 60 … 3600 s (setup, tray and the command
  line use 600 s by default), replaces any earlier code and clears the previous "last paired"
  result. The code's role is User or Admin; the first account of an empty list becomes an Admin
  anyway.
* Accepted input (`normalize_code`): `12345678`, `1234 5678`, `1234-5678`, `pair-12345678`,
  `pair_12345678` (prefix case-insensitive). Whitespace and dashes are removed; anything that is
  not then exactly 8 ASCII digits is malformed (input longer than 64 characters is not even
  normalized).
* `redeem(input, telegram_user_id, now)`:
  1. A sender who made 5 wrong guesses (`MAX_WRONG_PER_USER`) within the current hour
     (`USER_WINDOW_SECS`, across codes) gets `Wrong` without any comparison; the code is not
     touched, so a blocked sender cannot burn it.
  2. No code → `NoActiveCode`; invalidated code → `Exhausted`; expired → `Expired` (the code is
     dropped). None of these count as a guess.
  3. Malformed input → `Wrong`, counted neither against the code nor the sender (a bare `/pair`
     from Telegram's command menu is no guess).
  4. Constant-time comparison (`ct_eq`). Success consumes the code (single use) and returns its
     role.
  5. A wrong guess counts against the code — after 5 wrong guesses in total
     (`MAX_WRONG_PER_CODE`, all senders together) it is invalidated and stays inactive until a new
     one replaces it — and against the sender (table of at most 256 senders; expired windows are
     pruned first, then the oldest entry).
* `status(now)` → `PairingStatus { active, expires_unix, last_paired }` — never the code. The
  expiry time identifies "our" code to a client without revealing it (`ipc::pairing_progress`:
  Waiting, Paired, Expired, Replaced, Invalidated).
* `PairingCode`'s `Debug` prints `<hidden>`. Codes are never logged, never sent to Telegram and
  never written to disk; the only place they travel is the IPC reply to the client that asked.

### Redeeming a code in Telegram (`telegram/bot.rs`)
* `/pair CODE` (also `/pair@YourPcBot CODE`) and the deep link
  `https://t.me/YourPcBot?start=pair-12345678` (Telegram then sends `/start pair-12345678`) are
  recognized by `pairing_payload` **before** the authorization check: a pairing code is the only
  thing an unauthorized sender can use.
* `try_pair`: the sender must be a person (not a bot) with an id > 0 writing in their own private
  chat (`chat.id == from.id`); an account that is already authorized gets the ordinary denial
  there. Then `redeem`. On success the account is added (`add_user` with the display name, the
  code's role and `added_unix = now`), the result is recorded for `PairingStatus`, a security-log
  line is written, the reply is `✅ Paired with DESKTOP-01. Send /menu to start.` with
  `[🏠 Open Menu]`, and `👤 NEW TELEGRAM USER PAIRED` (Name, User ID, Role, Computer) is queued for
  every other user (`emit_notice(Security, …, exclude = [new id])`; kept in the chat, §12). The
  pairing message and the reply are short-lived chat messages like any other command.
* Every failure — no code, wrong code, expired, invalidated, rate-limited sender, 20 accounts
  already paired, `settings.json` not writable — is answered exactly like any other unauthorized
  message (`deny_message`, §7): at most one generic `⛔ Access denied. This bot is private.` per
  sender per hour, the reason only in the local security log, and the message text in logs and
  alerts as `/pair (pairing code hidden)`. An outsider cannot tell whether a code exists.
* An authorized user who sends `/pair …` or opens a pairing link in their own chat gets
  `ℹ️ You are already paired.` plus how pairing works; the code is neither compared nor used up.

### Where codes come from

| Source | Path | Role of the new account | Caller needs |
|---|---|---|---|
| Tray "Pair Telegram User…" | IPC `StartPairing { ttl_secs: 600, admin: false }` | User (Admin if it is the first) | the tray owner's account (no elevation) |
| Setup menu "2 Pair a Telegram user" | `pair_interactive` (asks "Make this account an Admin?") | User or Admin | elevated (setup always is) |
| Setup wizard, step 3 | `pair_interactive(admin = true)`, direct path (the service is not installed yet) | Admin | elevated |
| `predator-service pair [--admin] [--ttl SECS]` | through the running service, otherwise direct | User, or Admin with `--admin` | tray owner for User codes through the service; elevation for `--admin` and for the direct path |

Command-line pairing (`service/pairing.rs`):
* `route(is_default, service state)`: Running → through the service; Stopped / NotInstalled →
  direct; StartPending / StopPending / Paused / Unknown → refused with an explanation. Two
  consumers of `getUpdates` would steal each other's updates (Telegram answers 409 Conflict to the
  second), and a starting service has already read `settings.json`. A custom `--data-dir` always
  uses the direct path.
* **Through the service:** `Status` first (refuses when the service reports `not configured` or
  `invalid token`, notes when it is offline), `ListUsers` (to tell whether this is the first
  account), then `StartPairing`. The console prints the code as `1234 5678`, its validity and
  role, the deep link and the `/pair 12345678` message, then asks `PairingStatus` every 2 s until
  the account is paired, the code expires, is replaced or invalidated, or the service stops.
  Ctrl+C / Ctrl+Break (a console control handler) cancels **only its own code**: it asks
  `PairingStatus` first and sends `CancelPairing` only while that reply still shows the code it
  created waiting (or when no usable reply arrives); a code that the tray or another console
  created meanwhile is left alone. Closing the console window does the same with 1.5 s time
  limits.
* **Direct path** (`pair_direct`; elevated, trusted data directory): loads the token (a
  user-scope `U` blob is refused with instructions), `getMe`, refuses at 20 accounts,
  `deleteWebhook`, then `getUpdates(offset = -1, timeout = 0)` to drop the backlog **before** the
  code exists — no earlier message can contain it, and wrong guesses queued in advance would
  otherwise burn the new code at once. Consequence: messages sent to the bot while the service was
  stopped are discarded. The code lives in a local `PairingSlot` with the same rules as the bot;
  long polls are at most 25 s and never run past the expiry. Accepted: `/pair CODE` and
  `/start pair-CODE` from private chats with `chat.id == from.id`. Failed attempts are never
  answered (they are only printed locally); an already authorized account gets "already paired"
  and the code stays valid. A 409 Conflict while the service is now running or starting ends the
  pairing ("The Vigil service was started meanwhile…"); other errors, including a 409 from
  another program, are retried every 3 s. After success the consumed updates are confirmed (not
  while the service polls), `telegram-state.json` is written with the bot id (the service resumes
  after them), `NEW TELEGRAM USER PAIRED` is queued in `queue.json` for the other accounts (only
  while the service does not run), and a service that started meanwhile is asked to reload its
  settings. Ctrl+C simply ends the process; the code existed only there.

### Listing and removing accounts
* Telegram `/users` (any paired account, §7): every account with name, id, role and date added.
  Admins get one `🗑 Remove <name>` button per other account (`um:rm:<id>`). Removing is
  immediate (no confirmation, §7), refused for non-admins (`Only admins can remove users.`), for
  the admin's own entry and for the last Admin. A backlogged remove press is not executed (§7).
  The removed account's pending power confirmation is discarded, a security-log line is written
  and `🗑 TELEGRAM USER REMOVED` (Name, User ID, Role, Removed by) is queued for every remaining
  account.
* IPC `ListUsers` (tray "Telegram Users…" — a list only; `users list`; setup menu 3) and
  `RemoveUser { id }` (`users remove ID`; setup menu 3). `RemoveUser` needs LocalSystem or an
  elevated administrator; its notice says `Removed by: tray/CLI on this PC (user DOMAIN\alex)`.
* While the service does not run, `users list` reads `settings.json` and `users remove` edits it
  directly (elevated) and queues the notice in `queue.json` for the remaining accounts. While it
  runs but does not answer, `users remove` refuses: editing the file behind its back would leave
  the account authorized in the service's memory.
* `set-owner --telegram-id ID` replaces every account by this one Admin (revocation in one step);
  it queues no notice.

Alerts and notices go to every paired account, each delivery recorded per recipient (§8,
*Sender*).

## 7. Telegram UI specification

Parse mode **HTML** everywhere. Every dynamic value goes through `notify::format::esc` (truncate,
control characters → spaces, bidirectional-text controls removed, then `escape_html`).

### Authorization (every update, before anything else)
* An account may use the bot when its numeric id is in `settings.authorized_users` (§6). While
  nobody is paired, everything except a pairing code is rejected.
* A message is accepted only if `chat.kind == "private"` AND `from.id` is authorized AND
  `chat.id == from.id`. A callback is accepted only if `callback.from.id` is authorized and its
  message's chat is private with that same id.
* Pairing attempts (`/pair …`, `/start pair-…`) from anyone else are handled first (§6).
* Never use usernames for authorization.
* Group/supergroup/channel messages, edits, button presses and `my_chat_member` updates of a
  non-private chat → `leave_chat` + security log. A private `my_chat_member` (bot blocked or
  unblocked) is only logged at debug level.
* Edited messages are never executed. Messages without a sender are ignored (security log).
* Unauthorized private messages (including failed pairing attempts) → `security.log` through
  `security_untrusted("tg:<id>")`: id, @username, display name (≤ 64 chars), chat id, the first
  64 chars of the text (pairing codes hidden) and, for a failed pairing, the reason. Reply
  `⛔ Access denied. This bot is private.` and alert every paired account with
  `ctx.emit_security("UNAUTHORIZED ACCESS ATTEMPT", lines)` (User ID, Username, Name, Message) —
  both at most once per sender per hour (tracking table bounded at 256 senders).
* Unauthorized callbacks → `answer_callback("⛔ Not authorized", alert)` + security log (no alert
  to the users).

### Stale commands and backlogged button presses
State-changing commands (`/shutdown` `/restart` `/sleep` `/hibernate` `/lock` `/logout`
`/tailscale up` `/tailscale down`) whose `message.date` is older than `settings.stale_command_secs`
(300 s) are NOT executed; reply
`⌛ Ignored /lock sent at 14:02:11 — older than 5 minutes (sent while the PC was offline?)`.
A missing date counts as stale. Read-only commands are answered normally.

A callback query carries no timestamp. The poller therefore marks updates as *backlog*
(`handle_update_with(u, true)`) when they come from the first getUpdates batch after a process
start, after the bot changed, or after more than 90 s without a successful getUpdates (monotonic
and wall clock). Backlog batches are fetched with `timeout=0`, so they contain only updates that
were already queued; catching up continues while a batch comes back full (100 updates). For a
backlog update, state-changing callbacks — `act:lock`, `act:logout`, `ts:up`, `ts:down`, `ft:*`,
`pw:*`, `cf:*` and `um:rm:*` (`CallbackAction::changes_state`) — are NOT executed: the callback is
answered, a warning is logged (nonces redacted), and the pressed message is edited (send as
fallback) to
`⌛ Ignored a button press that was queued while Vigil was offline. Press it again if you still want this.`
with a keyboard offering the same button again (feature toggles for `ft:*`, `[🛡 Tailscale]
[⬅️ Back]` for `ts:*`, `[👥 Users] [⬅️ Back]` for `um:rm:*`, the main menu otherwise). A
backlogged `cf:<nonce>` also takes and discards the matching pending confirmation. `nav:*`,
`cx:*` and `um:ls` work normally. Messages ignore the flag (their date drives the stale rule).

### Commands
`/start`, `/menu` → main menu · `/help` · `/status` · `/network` · `/battery` · `/history` ·
`/features` · `/shutdown` `/restart` `/sleep` `/hibernate` (confirmation) · `/lock` `/logout`
(immediate) · `/cancel` · `/clear` (delete every tracked short-lived message of this chat now,
§12) · `/tailscale` (status + buttons) · `/tailscale status|up|down` · `/users` (paired accounts;
admins can remove them) · `/pair CODE` (only meaningful for a new account, §6).
The `setMyCommands` list (`Bot::command_list`) registers `menu status network battery history
features tailscale lock logout shutdown restart sleep hibernate cancel clear users pair help`.
Commands may have a `@botname` suffix (`/status@YourPcBot`) — it is stripped.
Unknown command → `❓ Unknown command. Send /help for the list.` `/tailscale <other>` → usage
text. Plain text → `ℹ️ I only understand commands. Open the control panel with /menu or see
/help.` with `[🏠 Open Menu]`.

### Confirmation policy (strict)
ONLY shutdown, restart, sleep and hibernate require confirmation. Everything else (lock, logout,
network, battery, Tailscale status/up/down, features, feature toggles, removing a user) executes
immediately — no extra dialogs anywhere. The *Power Management* feature gates all six actions:
shutdown, restart, sleep, hibernate, lock and logout.

Confirmation flow:
1. `/shutdown` (or the Shutdown button) → if Power Management is disabled → rejection message.
   Else `sys.check_power(action)`; if Err → `❌ Shutdown is not available: …`. Else create a
   pending confirmation `{action, nonce: rand::hex(16), created: Instant, created_unix, chat_id,
   message_id}` — **one per chat, i.e. per user**. The table holds at most 20 entries; when it is
   full, the oldest entry of another chat gives way. A newer request of the same user replaces
   that user's older one, whose message is edited to
   `⏭ Superseded — this shutdown request was replaced by a newer one.`; other users'
   confirmations are independent. Message:
   ```
   ⚠️ <b>CONFIRM SHUTDOWN</b>

   🖥 Computer: <code>DESKTOP-01</code>
   Open apps will be closed. Unsaved work may be lost.
   ⏳ Expires in 1 minute.
   ```
   Buttons: `[✅ Confirm Shutdown]` (`cf:<nonce>`) `[❌ Cancel]` (`cx:<nonce>`).
2. Confirm pressed → atomically TAKE the pending entry **of this chat** whose nonce matches
   (constant-time compare) — a user can only ever confirm their own dialog, and only once. Then:
   * the account is gone or was paired after the dialog was created (removed and paired again
     meanwhile, `added_unix > created_unix`) → dialog edited to
     `⌛ Confirmation expired. Send /shutdown again.`, alert `This confirmation is no longer valid.`;
   * expired (`settings.confirm_timeout_secs`, default 60 s) → the same edit, toast
     `⌛ Confirmation expired.`;
   * Power Management disabled meanwhile → disabled screen;
   * otherwise toast `⏻ Shutdown…`, edit to `⏳ Shutting down…`, security log, `sys.execute_power`,
     then edit with the result `✅ Shutdown initiated — DESKTOP-01 will power off in 5 seconds.`
     or `❌ Shutdown failed: …`.

   A wrong or used nonce → alert `This confirmation is no longer valid.`
3. Cancel button or `/cancel` → clears the caller's own pending confirmation and edits its message
   to `❌ Shutdown cancelled.` (`/cancel` also replies with that text); `/cancel` with nothing
   pending → `ℹ️ Nothing to cancel.` (an already expired dialog is edited to
   `⌛ Confirmation expired…` and gets the same reply). `/cancel` does nothing else (it does NOT
   abort an already initiated shutdown) and never touches another user's confirmation.
4. Chat cleanup (§12): the dialog message is *protected* (never deleted) while it can still be
   confirmed; it is released when it is confirmed, cancelled, superseded or expired (an expired
   one is released by the next message of that user or by the poller's sweep). `/clear` takes and
   discards the caller's pending confirmation and deletes its dialog.

Sleep/hibernate: the result says `💤 DESKTOP-01 is going to sleep now.` /
`🌙 DESKTOP-01 is hibernating now.` In dry-run mode the dry-run text returned by
`execute_power` is shown.

### Main menu (`/start`, `/menu`, `nav:main`)
```
🖥 <b>VIGIL REMOTE CONTROL</b>
━━━━━━━━━━━━━━━━━━
🟢 <b>Online</b> · <code>DESKTOP-01</code>
⏱ Uptime: 3h 12m · Service: 2h 5m
🔐 Login monitor: 🟢 Active · SSH: 🟢 Active
📬 Queued alerts: 0
```
Keyboard (callback data in parentheses):
```
[📊 System Status (nav:status)]
[🌐 Network (nav:net)] [🔋 Battery (nav:bat)]
[📜 Login History (nav:hist)] [⚙️ Features (nav:feat)]
[⏻ Shutdown (pw:shutdown)] [🔄 Restart (pw:restart)]
[💤 Sleep (pw:sleep)] [🌙 Hibernate (pw:hibernate)]
[🔒 Lock (act:lock)] [🚪 Logout (act:logout)]
[🛡 Tailscale (nav:ts)]
[❓ Help (nav:help)]
```
Navigation edits the menu message in place (`edit_message`, with a new message as fallback when
Telegram refuses the edit); sub-screens get `[🔄 Refresh (nav:<same>)] [⬅️ Back (nav:main)]`.
Slash commands send a new message. Every callback is answered (`answer_callback`) so the spinner
stops (errors ignored). Disabled features: button presses and commands reply
`🚫 <b>Battery Information is disabled.</b>\nEnable it in /features.` with `[⚙️ Features]
[⬅️ Back]`. Dry-run banner (main menu and status screen):
`🧪 <i>DRY-RUN mode — power, lock, logout and Tailscale up/down are simulated.</i>`

### Screens
* **System status**: computer, OS version, uptime (boot), service uptime and version, service RAM
  (private + working set, in MB with 1 decimal), service CPU time, Telegram status, monitors
  state, audit policy state, queued and delivered alerts, signed-in sessions (user ·
  Console/RDP · state · client address · 🔒 if locked; at most 10), dry-run banner if enabled.
* **Network**:
  ```
  🌐 <b>NETWORK STATUS</b>

  Connection: Wi-Fi
  SSID: ExampleWiFi
  IP Address: 192.168.1.105
  Internet: 🟢 Connected
  ```
  Ethernet: no SSID line. `ssid_note` in italics when the SSID is unavailable. A VPN line if any.
  The SSID comes from the `ssid-helper` child process (§8).
* **Battery**:
  ```
  🔋 <b>BATTERY STATUS</b>

  Battery: 85%
  Status: Charging
  Power: AC Connected
  ```
  (`Fully charged`, `Discharging (≈ 2h 10m left)`); desktops: `🔌 No battery detected — this PC
  runs on AC power.`
* **Login history**: last 10 `EventDetails` newest first, one compact line each:
  `🟢 25 Nov 14:30 · alex · Interactive` / `🔴 … · failed` / `🚪 … · logout` /
  `🔐 … · SSH 192.168.1.20`.
* **Features**: title `⚙️ <b>VIGIL FEATURES</b>` + one line per feature
  (`🟢 Windows Login Monitoring` / `🔴 Failed Login Notifications`), then two italic footnotes
  (toggles take effect immediately; `Power Management covers shutdown, restart, sleep, hibernate,
  lock and logout.`); keyboard: one toggle button per feature, 2 per row, text `🟢 Login Monitor`
  / `🔴 Failed Logins` (`ft:<index>`), plus `[⬅️ Back]`. Toggling edits in place immediately (no
  confirmation) and answers the callback with e.g. `SSH Monitoring disabled`. `/features` works
  even if every other feature is disabled.
* **Tailscale** (`nav:ts`, `/tailscale`, `/tailscale status`): installed (+ version), service
  state, `App: 🟢 Running` / `App: ⚪ Not running` (`TailscaleStatus.app_running`: is
  `tailscale-ipn.exe` running in any session — one process snapshot, no CLI call), connection
  line, Tailscale IPv4, hostname, tailnet, health warnings (max 3), login URL if present (with the
  warning that whoever opens it binds this PC to their tailnet).
  Connection line: whenever the Tailscale service is not running →
  `🔴 Disconnected (Tailscale service stopped|starting|stopping|paused|not installed)` (also right
  after a successful `/tailscale down`); otherwise `🟢 Connected`, `🔴 Disconnected` (backend
  Stopped), `🟡 Needs login`, `🟡 Needs admin approval (…)`, `🟡 In use by another Windows user`,
  `🟡 Starting…`, `🟡 Connecting…` (NoState), and `⚪ <state>` for anything unrecognised.
  Buttons `[▶️ Up (ts:up)] [⏹ Down (ts:down)]` (only when installed) `[🔄 Refresh] [⬅️ Back]`.
  Up/Down: no confirmation; first edit/send `⏳ Bringing Tailscale up…`, run on a worker thread
  (one Tailscale operation at a time; if busy `⏳ A Tailscale operation is already running.`),
  then edit with the step log (✅ / ℹ️ / ⚠️ / ❌ lines, at most 12) + the final status. Tailscale
  Management disabled → rejection. The steps themselves are described in §13.
* **Users** (`/users`, `um:ls`):
  ```
  👥 <b>TELEGRAM USERS</b> (2 of 20)

  👑 <b>@alex</b> · <code>123456789</code> · Admin · added 25 Nov 2026 <i>(you)</i>
  👤 <b>Sam</b> · <code>234567890</code> · User · added 26 Nov 2026
  ```
  followed by a note on roles and how to pair. An Admin viewer gets `[🗑 Remove Sam]`
  (`um:rm:234567890`) for every other account; everyone gets `[🔄 Refresh (um:ls)] [⬅️ Back]`.
  Results: toast `Removed Sam`; alerts `Only admins can remove users.`,
  `You cannot remove your own account here. Ask another admin, or remove it on the PC
  (Vigil.exe → Telegram users, or 'predator-service users remove ID').`, or the
  last-admin error. The list is edited in place afterwards.
* **Help**: grouped list of commands (Information, Power, Session, Tailscale, Users, Chat), the
  Power Management scope (all six actions), the Tailscale Management feature name, how a new
  account is paired, a *Chat* section (`/clear` and, when auto-clean is on, "deleted
  automatically when you send the next command or after <chat_clean_after_secs> without use …
  Login, logout and security alerts are always kept"; when it is off, a note naming
  `auto_clean_chat`), the confirmation policy (a confirmation can only be confirmed by the user
  who asked for it) and a security note (only paired accounts by numeric id, everyone else is
  reported to every paired user, stale commands, late button presses must be pressed again).

### Notification formats (`notify::format`)
`render_event`:
```
🔐 <b>NEW WINDOWS LOGIN</b>

🖥 Computer: <code>DESKTOP-01</code>
👤 User: <code>alex</code>
🔑 Login Method: Interactive
🌍 Source IP: 192.168.1.20        (only when present)
💻 Client: LAPTOP-02              (only when present)
🕒 Time: 14:30:25 · 25 Nov 2026
✅ Status: Successful
```
Titles: Login → `🔐 NEW WINDOWS LOGIN`; FailedLogin → `⚠️ FAILED WINDOWS LOGIN` (+ `❗ Reason:` and
`❌ Status: Failed`); Logout → `🚪 WINDOWS LOGOUT` (+ `📝 Type:` reason); SshLogin → `🔐 NEW SSH LOGIN`
(User, Source IP, Auth method, Key if in extra, Time, Status); SshFailed → `⚠️ FAILED SSH LOGIN`;
SshLogout → `🚪 SSH SESSION CLOSED`. Extra key/values appended before Time.

`render_system(emoji, title, lines, time)` renders lifecycle, security and user notices as
`<emoji> <b>TITLE</b>`, one `Key: value` line each (≤ 30 lines), then `🕒 Time: …`. Examples:
`🟢 VIGIL ONLINE`, `🔴 VIGIL GOING OFFLINE`, `☀️ VIGIL RESUMED`, `⚙️ FEATURE CHANGED`,
`⚠️ AUDIT POLICY INSUFFICIENT`, `⚠️ LOGIN MONITOR GAP` (kind System, auto-deleted, §12);
`🚨 UNAUTHORIZED ACCESS ATTEMPT`, `🚨 SECURITY LOG CLEARED`, `👤 NEW TELEGRAM USER PAIRED`,
`🗑 TELEGRAM USER REMOVED` (kind Security, kept).

`late_delivery_note` → `\n\n📨 <i>Delivered late — queued while offline (sent 15:02:11)</i>` for a
delivery at least 60 s after the event.
Failed-login rate limit: 10 alerts per 10-minute window keyed by event time; the rest are counted
and reported as `⚠️ FAILED LOGIN ALERTS SUPPRESSED` ("N failed login attempts suppressed between
HH:MM and HH:MM") when the window closes or with the next failure.

## 8. Service runtime

* **`main_entry`**: first `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` (§9). No
  arguments → run under the SCM (`StartServiceCtrlDispatcherW`); when that fails with
  `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063 — the program was not started by the SCM, e.g.
  a double-click) → the interactive setup (§9). `service` → SCM only (prints the usage on 1063).
  Subcommands (see `service/cli.rs` and `predator-service help`):
  `setup [--token-file F] [--telegram-id ID] [--yes]`, `pair [--admin] [--ttl SECS]` (60–3600,
  default 600; `--timeout SECS` is accepted as an alias and raised to at least 60, `--force` is
  accepted and ignored), `users [list | remove ID]`, `set-owner --telegram-id ID`,
  `install [--start]`, `uninstall [--keep-audit-policy] [--purge-data]`, `start`, `stop`,
  `status`, `set-token [--file PATH | --stdin] [--no-verify]` (hidden prompt without options),
  `set-owner-sid (--user NAME | --sid S)`, `features [list | enable KEY | disable KEY]`,
  `audit (status|enable|restore)`, `selftest [--tailscale]`,
  `console [--token-file F] [--stdin-commands] [--dry-run]`, `version`, `help`; common options
  `--data-dir DIR` and `--verbose`/`-v`. Internal (not in the usage text): `restart-helper`,
  `ssid-helper`, `extract-tray PATH` (used by `scripts/build.ps1`) and `setup --invoking-sid SID`
  (the elevated relaunch). `ssid-helper` is dispatched right after parsing, before any logging or
  data-directory setup, and returns `sys::network::ssid_helper_main()` (exit code 0, one JSON line
  `{"ssid":string|null,"note":string|null}` on stdout; extra arguments are rejected).
  `setup`, `install`, `uninstall`, `start` and `stop` refuse `--data-dir` (the service always
  uses the default directory; `commands::reject_custom_data_dir`).
  CLI commands that need admin rights say so clearly when not elevated.
* **`install`**: refuses when the exe folder or either exe can be modified by non-admins (SDDL
  check) or when `.dll/.ocx/.cpl/.local/.manifest` files sit next to the exe
  (`install::check_program_files`); prepares the data directory (trust check → move aside →
  atomic creation → strict `secure_data_dir` → check again, §19); sets the tray owner SID to the
  installing user when none is configured; creates or updates the service; enables the logon
  audit policy (saving `audit-backup.json` once); registers the HKLM Run value `PredatorTray`;
  prints the next steps (`set-token`, `pair --admin`, `start`). Setup uses the same
  `install::register` with the account that started setup as the tray owner (§9).
* **Service configuration** (`register`): own process, auto start, LocalSystem, depends on
  `EventLog`, description, failure actions restart after 5 s / 10 s / 30 s (reset 1 day; the
  last action repeats), `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 1`, preshutdown timeout 15 s, SID
  type unrestricted.
* **`uninstall`**: stops and deletes the service, removes the Run value, restores the audit
  policy (not from an untrusted directory or a backup with a foreign ACL). With `--purge-data`
  it deletes the data directory, except `audit-backup.json` when the restore failed; a failed
  restore makes the command return an error (non-zero exit) naming where the original values are
  kept. It does not delete the program files (the setup menu's Uninstall does, §9).
* **Control handler** accepts STOP | PRESHUTDOWN | POWEREVENT | SESSIONCHANGE. POWEREVENT
  PBT_APMRESUMEAUTOMATIC → `Runtime::on_resume` (interrupt + kick poller and sender, queue
  `☀️ VIGIL RESUMED` at most once a minute); PBT_APMSUSPEND is only logged. SESSIONCHANGE →
  `monitor::on_session_change`.
* **Fatal failures** (start failed, main thread panicked, `RegisterServiceCtrlHandlerExW` failed)
  are written to the Application event log (source `PredatorRemoteController`, event id 1000,
  plus `OutputDebugStringW`) and end the process with service-specific exit codes 1 / 2 / 3.
* **Startup**: `DataPaths::ensure_dirs` (as LocalSystem: atomic creation with the protected
  DACL); as LocalSystem `winsec::secure_data_dir(root, true)` (re-applies the ACL only when it
  drifted; it does not run the trust check); init logging; EcoQoS on
  (`util::win::set_eco_qos(true)`, §17; also in console mode); load settings/queue/history; load
  the token (`secrets::load_token` accepts both scopes; no scope migration) and create the
  `TelegramApi`, whose `HttpClient` decides the HTTPS transport now (§16; logged as
  `Telegram bot token loaded (HTTP transport: …)`); open the chat janitor
  (`ChatJanitor::open(chat-cleanup.json)`, never fails — a corrupt file is renamed to
  `chat-cleanup.json.corrupt`) and build `AppContext::with_janitor` (which also holds the empty
  `PairingSlot`); `RealSystem::new(dry_run, start)` (dry_run = settings.dry_run || DRY_RUN marker
  || console); `TelegramSlot`, `Bot::new`; audit status; start monitors, connectivity watcher,
  poller, sender, IPC server. If the token is missing/invalid the monitors still run and queue
  alerts; Telegram threads wait (re-check every 30 min, log once). Queue `🟢 VIGIL ONLINE`
  (computer, service started, version, boot time, dry-run mode) when
  `settings.lifecycle_notifications`.
* **Connectivity hint**: `net::connectivity::current()` is advisory. While it says Disconnected or
  LocalOnly, poller and sender wait on their wake signal at most `OFFLINE_RECHECK` = 60 s (ended
  early by a connectivity change, resume, new token or stop — not by queue pushes) and then try
  anyway. A success while the hint says offline sets `hint_overridden` (logged once); both loops
  then ignore the hint until a `TgError::Network` failure or a connectivity-watcher change.
* **Interrupting the long poll**: the connectivity watcher forwards only real level changes
  (repeated notifications of the same level are coalesced). `Shared::connectivity_changed` and
  `Runtime::on_resume` call `Shared::interrupt_long_poll` **before** `kick()`. The interrupt is
  done only while the poller is inside getUpdates (`long_poll_active`) and never once stopping.
  It bumps an interrupt generation and calls `TelegramApi::interrupt` → `HttpClient::interrupt`,
  which cancels **every** direct request in flight and closes the idle connections (they belong
  to the old network). `getUpdates` is `Interruptible::Always`; every other method is
  `Interruptible::UntilSent`, so it is cancelled only while connecting or sending, and once its
  request has been completely written it runs to its reply or time limit. A reply, edit or delete
  is never lost that way, and a `sendMessage` that Telegram may already have accepted is never
  reported as failed and then sent again. That is also why the interrupt comes before the kick: a
  delivery the kick starts must not be hit. The poller (and the sender) treat an error as an
  interrupt when the generation moved during the request and the error is `TgError::Network`,
  and retry at once (no backoff, DEBUG log only). With the WinHTTP backend the interrupt is a
  no-op; its long poll ends at its receive time-out (65 s).
* **Poller**: once per token generation `getMe` (refresh `bot_username`, bind the polling position
  to the bot id: same bot → keep; no stored id → adopt; different bot → discard the position and
  restart backlog handling, logged as a warning; the chat janitor is bound the same way with
  `ctx.janitor.bind_bot`), `deleteWebhook`, `setMyCommands(Bot::command_list())`.
  Loop: backlog decision (§7) → `get_updates(offset, 0 or 50)`; on success reset backoff, mark
  online, then for each update with id > persisted id: persist the id (with bot id), then
  `bot.handle_update_with(&u, from_backlog)`; kick the sender after a non-empty batch; then the
  chat sweep `sweep_service` (§12; skipped while stopping, one lock when nothing is tracked). The
  persisted id is trusted as offset/filter only when younger than 6 days (Telegram may assign
  random ids after a week without updates). Errors: Network/Server/409 → backoff 2 s…5 min
  (connectivity changes reset it); 429 → `retry_after`; 401 → token_invalid (re-check every
  30 min; a new `token.dat` is picked up then). After a handled batch the poller sets the
  activity mark (`Shared::note_activity`); after a cycle that returned no updates (the quiet
  point of the loop) it asks the `TrimPolicy` whether to trim the working set (§17).
* **Sender** (`service/sender.rs`): loop on `ctx.queue.front()`; nobody paired → keep queued (wait
  up to 30 min or until woken); compose the text (+ `late_delivery_note`); then one *delivery
  pass* (`deliver_pass`) over every authorized account that is not yet in the item's
  `delivered_to`:
  * each success is recorded at once (`NotificationQueue::mark_delivered`, written like an ack) and
    a delivered `System` notice is handed to the chat janitor of that recipient's chat
    (`track_delivered`; login/logout/failed/SSH/security alerts are not, §12); an account removed
    during the pass gets nothing more;
  * a retryable error (network, server, 429) ends the pass — the accounts reached so far stay
    recorded, so after the backoff or a restart only the others get it;
  * `403` or a "chat not found / user not found / bot was blocked / user is deactivated" answer
    for one account (it blocked the bot or never pressed Start) skips that account (warned once
    per account) as soon as anyone else has the notification; when nobody can be reached, the
    item stays queued and is retried every 30 min;
  * `BadRequest` (e.g. HTML rejected) → retried once as plain text (tags stripped), then dropped
    with a log line;
  * once every current account is covered, the item is acked (coalesced: written at most every
    2 s, at once when the queue becomes empty; pending writes are flushed before every wait, §17),
    `note_activity`, `status.delivered += 1`.

  Accounts paired later also receive what is still queued. The "going offline" notice at stop
  uses the same pass (§2). On retryable errors the sender backs off 2 s … 5 min waiting on
  `ctx.sender_wake` (a connectivity change resets it); 401 marks the token invalid.
* **IPC server** (`ipc_server.rs`): pipe `\\.\pipe\PredatorRemoteController`, DACL
  `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)` (interactive users read/write
  without FILE_CREATE_PIPE_INSTANCE), first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  `PIPE_REJECT_REMOTE_CLIENTS`. One JSON request line (≤ 4 KiB, 1.5 s read timeout) per
  connection. The client is identified by identification-level impersonation (token SID,
  elevation, enabled Administrators membership — local queries only; account names are looked up
  only for log lines, cached 1 h, ≤ 16 entries) and authorized: LocalSystem, the configured owner
  SID (`owner_windows_sid`), or an elevated administrator; everyone else gets `Denied` (logged via
  `logging::security_untrusted("ipc:<SID>", …)`). Some requests additionally need a *privileged*
  caller (LocalSystem or an elevated administrator — the owner SID alone is not, because every
  unelevated process of the owner's session runs with it); an authorized but unprivileged caller
  gets `Error` with an explanation (rate-limited security log). Requests:
  * `Status` → `ServiceStatusInfo` (Tailscale from the cache only; `owner_configured` = at least
    one account paired; `transport` = the HTTPS backend in use, `None` while no token is loaded).
    `predator-service status` prints it as `HTTPS transport: …`;
  * `SetFeature` → `settings.set_feature` + security log
    `feature <key> enabled|disabled via local IPC (tray or CLI) by <DOMAIN\user> (<SID>)` + system
    notification `⚙️ FEATURE CHANGED` (Feature, State, `Changed by: tray/CLI on this PC (user …)`);
    the same request serves the tray and `predator-service features enable|disable`. Changes made
    in Telegram are logged `via Telegram`;
  * `ReloadSettings` → `SettingsStore::reload_from_disk()`; when something changed, a security-log
    line names what (Telegram users, tray owner SID, bot username, features, options), the sender
    is kicked, and the reply is `Ok "Settings reloaded by the running service"`; otherwise
    `Ok "Settings unchanged"`, or `Error`. A changed `dry_run` takes effect at the next start;
  * `TailscaleStatus` (worker) → live status unless Tailscale Management is off;
  * `RestartService` (worker, service mode only) → spawn detached
    `predator-service.exe restart-helper --data-dir <root>` (stops + starts the service via SCM);
    security log `service restart requested via local IPC (tray or CLI) by <user> (<SID>)`;
  * `StartPairing { ttl_secs, admin }` → refused at 20 accounts; `admin: true` needs a privileged
    caller; creates (replaces) the code and answers `Pairing { code, expires_unix, bot_username }`.
    The code goes to this caller only; the security log records who created a code, its role and
    validity, never the code;
  * `PairingStatus` → `PairingState { active, expires_unix, paired_name, paired_id, paired_unix }`
    (never the code);
  * `CancelPairing` → forgets the active code (security log when one was active);
  * `ListUsers` → `Users { users: [{id, name, role, added_unix}] }`;
  * `RemoveUser { id }` → privileged callers only; last-admin rule; revoked at once; security log;
    `🗑 TELEGRAM USER REMOVED` to every remaining account.

  Quick requests (everything except `TailscaleStatus` and `RestartService`) are answered on the
  accept thread. The client side (`ipc::request`) verifies that the pipe server PID equals the PID
  the SCM reports for the service; `ipc::request_to_pid` takes a PID the caller already queried.
* **CLI ↔ running service**: `set-owner`, `set-owner-sid`, `features enable/disable` (when the IPC
  `SetFeature` request cannot be delivered and the CLI edits `settings.json`), `set-token` (bot
  username changed), a direct `pair` that
  finished after the service started, and setup's token change and `--telegram-id` call
  `commands::tell_service_settings_changed`, which sends `ReloadSettings` while the default service
  is running and prints the restart command when that fails. A new token itself is used after a
  restart. `pair` and `users` go through IPC while the service runs (§6).
* **HTTPS in CLI commands**: `selftest`, `set-token` (verification), setup's token check (`getMe`)
  and the direct `pair` path create their own `TelegramApi` in the CLI process. Their transport is
  chosen from the CLI process's environment and the Internet Settings of the account running it,
  so it can differ from the service's; `selftest` prints it as `Telegram HTTP transport: …`. The
  service's own transport is what `status` reports.
* **Console mode**: same runtime in the foreground (Ctrl+C, Ctrl+Break, closing the console or the
  end of standard input stops it). `--stdin-commands`: each stdin line is injected as a message
  from the primary authorized account (`/network`) or a callback (`cb:nav:feat`, using a fresh
  menu message id) so the full dispatcher can be tested end-to-end. Console mode ALWAYS forces
  dry-run (power/lock/logout/Tailscale up+down are simulated); there is no flag to disable that.
  The IPC server is disabled when the pipe cannot be created (e.g. while the service runs).
* **Network info** (`sys/network.rs`): route and interface classification run in-process; only on
  Wi-Fi is `<exe dir>\predator-service.exe ssid-helper` started through
  `process::run_with_timeout` (hidden, kill-on-close job, 8 s). The helper resolves the Wi-Fi
  interface itself and tries WLAN API → WinRT `GetConnectedSsid` → NLM on its main thread. The
  parent cleans and length-limits the reply (SSID ≤ 64 chars, note ≤ 200); any failure becomes
  `ssid = None` plus a note.

## 9. Single-file release and setup

### The release file
`Vigil.exe` is `predator-service.exe` built with the Cargo feature
`embed-tray`: `scripts/build.ps1` builds `predator-tray.exe` first and then the service with
`PREDATOR_EMBED_TRAY=<full path of that tray>`. `build.rs` checks the file (absolute path, at least
1 KiB, `MZ` header) and passes its SHA-256 on as `PREDATOR_EMBED_TRAY_SHA256`;
`setup/embedded.rs` includes the bytes (`include_bytes!`) in the read-only data section. They are
never touched — so never paged in — unless setup extracts them, which keeps the installed service's
memory use unchanged. A build without the feature installs the `predator-tray.exe` found next to
the executable instead. Installed, the same image is called `predator-service.exe`.

### Start without arguments
1. `main_entry` → SCM dispatcher; error 1063 (not started by the SCM) → `setup::run`.
   `predator-service setup [...]` enters the same code directly.
2. Setup refuses `--data-dir`. Not elevated → it relaunches its own executable with
   `ShellExecuteExW("runas")` (UAC prompt) and the arguments `setup --invoking-sid <SID of the
   starting account>` plus the options given (a relative `--token-file` is made absolute),
   waits for it and passes its exit code on. A declined prompt changes nothing. The token itself
   is never passed on a command line.
3. Elevated: `--invoking-sid` is validated (`winsec::canonical_sid`, never LocalSystem) and
   becomes the tray owner; without it the account of the elevated process is used. The two differ
   when another administrator's credentials were typed into the UAC prompt.
4. Service installed → the management menu (or, with `--yes`, the unattended update path);
   otherwise the wizard. The console window waits for Enter at the end when it belongs to this
   process only (it would close at once otherwise) — never with `--yes`.

### Wizard (`wizard.rs`; the machine side is `actions.rs`)
An overview (program folder, data folder) and "Install now?", then six steps:
1. **Telegram bot token** — a short @BotFather guide, hidden input (`ask_secret`), whitespace
   removed, format check (`is_valid_token_format`), `getMe` (must be a bot account), at most 5
   attempts; Enter alone cancels. A token already stored in a *trusted* data folder can be kept.
   `--token-file F` replaces the prompt.
2. **Protected data folder** — `install::prepare_data_dir` (trust check; an untrusted folder is
   moved aside; atomic creation with `DATA_DIR_SDDL`; strict re-secure; check again, §19), then
   the token is stored with DPAPI (machine scope) and the bot username written to `settings.json`.
3. **Link your Telegram account** — the first account is paired as Admin
   (`pair_interactive(admin = true)`; direct path, the service is not installed yet, §6). On
   failure: try again, or continue without an account (pair later from the menu). With accounts
   already present (kept data folder) it offers to pair another Admin. `--telegram-id N`
   authorizes N as Admin without pairing.
4. **Program files** — `files::install_program` into `<ProgramFilesDir>\Predator` (see *Program
   files* below).
5. **Windows service** — `install::register` (data directory, tray owner = invoking account,
   service create/update and configuration, logon audit policy, HKLM Run value) and start (40 s).
6. **Tray icon and Tailscale** — the tray is started in the signed-in session through Explorer
   (below); then a short "Why Tailscale?" text and a read-only Tailscale check (status only, never
   `up` or `down`) with advice (install Tailscale, enable *Run unattended*).

A summary follows (folders, service state, bot, accounts, tray, Tailscale). Nothing is rolled back
when a step fails; running setup again continues where it stopped. Unattended install:
`setup --token-file F --telegram-id N --yes` (both are required unless a kept trusted data folder
already has a token and accounts).

### Management menu (`menu.rs`)
```
Vigil 1.0.0 - installed
  Service: Running | Bot: @YourPcBot | Telegram users: 2
  Installed in C:\Program Files\Predator (version 1.0.0)

  1  Status
  2  Pair a Telegram user
  3  Telegram users (list / remove)
  4  Change bot token
  5  Update installed program to this version (1.0.0)
  6  Open the bot in Telegram
  7  Uninstall
  0  Exit
```
* **1** `status` plus program/data folders and the Tailscale advice.
* **2** asks "Make this account an Admin (can also remove users)?", then `pair_interactive`
  (through the running service, §6).
* **3** lists the accounts; typing an id (and confirming) removes it (`users remove`).
* **4** the token dialog of the wizard; the token is stored and the running service can be
  restarted to use it. Paired accounts stay authorized; with a token of a different bot every
  account has to open the new bot and press Start once.
* **5** is offered only when the running file differs from the installed one (path and SHA-256
  compared): *Update with rollback* below.
* **6** opens `https://t.me/<bot>` in the signed-in user's browser through Explorer.
* **7** *Uninstall* below; asks whether the data folder is deleted too.

`--yes` on an installed PC: update when the running file differs, store `--token-file` (and
restart a running service), authorize `--telegram-id` as Admin, then print the status.

### Program files (`files.rs`)
* `prepare_install_dir` refuses a folder that is not absolute, a drive root or top-level folder, a
  system folder (Windows, System32, Program Files itself, ProgramData, the user profile folders),
  a junction or symbolic link, or an existing folder holding files that are not Vigil's (no
  Vigil executable or leftover in it). A new folder is created atomically with
  `INSTALL_DIR_SDDL` =
  `O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;RC;;;OW)`
  (SYSTEM + Administrators full, Users read/execute, OWNER RIGHTS only READ_CONTROL); an existing
  one gets the same owner and protected DACL. Afterwards nobody but SYSTEM and administrators may
  be able to write to it and the DACL must be protected, otherwise setup stops.
* Before installing, loadable modules (`.dll/.ocx/.cpl/.local/.manifest` — Vigil ships none) and
  leftovers of interrupted runs are removed from the folder (`clean_dir`).
* Images: the service image is this executable's own bytes; the tray is the embedded copy,
  verified against the SHA-256 recorded at build time before anything is written.
* `stage`: a file that already has exactly the expected bytes stays (`Unchanged`); otherwise a
  new `<name>.new-<8 hex>` is created inside the protected folder (so it gets its ACL) with
  `create_new`, written, `fsync`ed, read back and its SHA-256 compared. `commit`: the current file
  is renamed to `<name>.old-<8 hex>` (a running program can be renamed, not overwritten), the new
  copy takes its name; renames are retried briefly (an antivirus scanner may hold a fresh file).
  `finish` deletes the `.old` file, or — when it is still in use — schedules it for deletion at
  the next restart (`MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)`). `rollback` restores the previous
  file.

### Update with rollback (`actions.rs`)
1. `install::check_program_files` on the installed folder: an unprotected folder is not updated.
2. Stage service and tray; both unchanged → "already this version".
3. Stop the service (40 s; failure → discard, abort) and every `predator-tray.exe` whose image is
   exactly the installed tray (image check and termination on the same process handle).
4. Commit the service, then the tray; a failed commit rolls back and restarts the previous
   version.
5. `install::register` with the new version's configuration, then start the service (40 s).
6. The new version does not start: if the old one was running, stop the pending start, roll both
   files back, start the previous version and report the failure; if it was not running before
   either, the update stays (with a warning).
7. Success: the `.old` files are deleted (or scheduled), the tray is started again.

### Uninstall (menu 7)
`install::uninstall_steps` (stop and delete the service, remove the Run value, restore the audit
policy, optionally delete the data folder). Only when the service registration is gone: stop the
installed trays and `remove_install_dir`, which deletes only Vigil's own files —
`predator-service.exe`, `predator-tray.exe` and `.new-*` / `.old-*` leftovers, and in a dedicated
folder named `Vigil` also Vigil's README, `assets\predator*.ico` and `docs\*.md`. It never
follows junctions or symbolic links, never descends into folders it does not know, removes the
folder only when it is empty and lists what it kept. Files in use are renamed to `.old-<hex>` and
deleted at the next restart. A folder that does not look like Vigil's is refused.

### Acting as the signed-in user (`desktop.rs`)
The elevated setup never starts the tray or a browser elevated. It hands the target (installed
tray path or an `https://t.me/...` link) to `explorer.exe` from the Windows directory, which passes
it to the shell already running in the session, so it starts as the signed-in user at normal
integrity. This is done only when an Explorer shell runs in the same session and belongs to the
same account as the setup process; otherwise it is skipped (the tray then starts at the next
sign-in through the Run value). A tray start is confirmed by finding a `predator-tray.exe` with the
installed image in this session within 6 s.

### DLL-planting hardening
The release file is typically started — and elevated — from a download folder, where a planted
`version.dll` or similar would otherwise run as administrator:
* `main_entry` first calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`: DLLs loaded
  later by name (delay-loaded imports, on-demand system DLLs) come from System32 only.
* The service image is linked with `/DEPENDENTLOADFLAG:0x800` (`LOAD_LIBRARY_SEARCH_SYSTEM32`
  for the static imports, honoured since Windows 10 1607), so even imports that are not KnownDLLs
  (secur32, crypt32, iphlpapi, wevtapi, …) never come from the executable's folder.
* `shell32.dll` is delay-loaded: only setup's `ShellExecuteExW("runas")` needs it, so it is never
  mapped into the running service.
* `install` and setup refuse to register a service whose folder contains loadable modules, and
  setup removes them from the program folder (above).

## 10. Tray

GUI-subsystem, single instance per session (named mutex `Local\PredatorRemoteControllerTray`). A
hidden top-level tool window (not message-only, so the `TaskbarCreated` broadcast reaches it) +
`Shell_NotifyIconW` (NOTIFYICON_VERSION_4, re-add on `TaskbarCreated`). Icons from resources:
id 1 = normal, id 2 = service-stopped variant. Tooltip, e.g.
`Vigil\nService: Running\nTelegram: online\nTailscale: service running · Connected · 100.64.0.5`.
The Tailscale line is always present: `service running[ · <cached summary>]`, `service stopped`,
`service starting`, `service stopping`, `service paused`, `not installed`, `management disabled`
(when the service reports Tailscale Management off) or `unknown`; the SCM state of the `Tailscale`
service wins over the service's cached summary.
The tray exits silently when the service answers `Denied` (its account is not the tray owner).

Event-driven refresh (`tray/watch.rs`, decisions in `tray/model.rs`):
* The UI thread idles in an alertable `MsgWaitForMultipleObjectsEx(QS_ALLINPUT, MWMO_ALERTABLE |
  MWMO_INPUTAVAILABLE)`. `NotifyServiceStatusChangeW` watches the Vigil service (unless it is
  not installed), and the `Tailscale` service unless Tailscale Management is reported off or that
  service is not installed or its state unknown (`should_watch`).
  Windows delivers each notification as an APC to that thread; the callback only copies the
  result into a thread-local cell and posts `WM_SVC_NOTIFY`. The window procedure decides
  (`notify_action`): same state and PID → re-arm only; changed state or PID → refresh and re-arm;
  `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` → reopen; delete pending or failure → close the handle
  (an open handle would keep a service being uninstalled from being deleted) and let the polling
  refresh retry after `WATCH_RETRY` = 55 s. Storm guard: more than 30 notifications in 60 s close
  the watch for 10 min. One `SERVICE_NOTIFY_2W` buffer per target lives for the whole process and
  is reused only when no registration is outstanding.
* The watches are closed while a menu or dialog is open (`WatchPause`: APCs are not delivered
  inside modal loops) and reopened afterwards; a new watch reports the current state at once, so
  nothing is missed.
* Periodic refresh (`TIMER_REFRESH`, `SetCoalescableTimer`): `SAFETY_REFRESH` = 5 min (30 s
  tolerance) while the Vigil service is watched and settled, for what the SCM does not report
  (Telegram state, features, Tailscale summary); `POLL_REFRESH` = 60 s (5 s tolerance) while it is
  not watched, or while it runs without answering the status request or answers that Telegram is
  offline (`refresh_period`). Also: on menu open, after every action, and one follow-up refresh
  15 s after Start/Restart Service or after a notification showed the service (re)started.
* A refresh = one SCM query of the Vigil service (state + PID), IPC `Status` through
  `ipc::request_to_pid` with that PID (no second SCM round trip; user actions still use
  `ipc::request`, which asks the SCM itself), plus one SCM query of the `Tailscale` service unless
  the service reports Tailscale Management off (`tailscale_wanted`). It never spawns Tailscale.
* Pairing check: only while a code created by this tray is active, a one-shot timer
  (`TIMER_PAIRING`, 5 s, coalescable, re-armed after each check) asks `PairingStatus`. It stops
  when the code was used (balloon `Telegram account paired` — `Paired: <name> (Telegram id N)`),
  expired (balloon), became invalid (balloon), was replaced by another code (silently), or 30 s
  after the expiry when the service does not answer. No timer runs otherwise.

Footprint: `ImmDisableIME(-1)` at start (linked `raw-dylib` from `imm32`; the tray takes no text
input, so the IME / Text Services Framework is never loaded; measured: about 0.1–0.2 MB less
private memory and 0.8–1.4 MB less working set). The tray trims its working set after start-up,
after each menu or dialog, and after a periodic refresh when the last trim is at least 5 min old.

Context menu (`model::build_menu`):
```
Open Dashboard                 (https://t.me/<bot_username>; greyed without a username)
Service Status                 (MessageBox; live TailscaleStatus only when the service answers,
                                Tailscale Management is on and Tailscale is installed)
Pair Telegram User…            (enabled while the service answers; IPC StartPairing, User role,
                                10 minutes; dialog with code, deep link and /pair message)
Telegram Users…                (enabled while the service answers; IPC ListUsers, list only —
                                removing is done with /users from an Admin or in the setup menu)
───────────
Disable|Enable Login Monitoring    quick toggles: "Disable X" + check mark while on,
Disable|Enable SSH Monitoring      "Enable X" while off, greyed "Enable/Disable X" while the
Disable|Enable Notifications       state is unknown. Notifications = Login Notifications,
Disable|Enable Power Management    Tailscale = Tailscale Management
Disable|Enable Tailscale
Feature Settings ▸             (all 9 features by name with check marks)
───────────
Start Service (admin)…         (only while stopped/paused/unknown; greyed when not installed;
                                ShellExecute "runas" <exe dir>\predator-service.exe start)
Restart Service                (always listed; greyed unless running; IPC RestartService)
Exit Tray Application
```
The pairing dialog says that the first account becomes an Admin, that other accounts get the role
User, and that whoever sends the code first gets access (Ctrl+C copies the dialog text).
`--lock` argument → call `LockWorkStation()` and exit with 0 or the Win32 error (session helper,
no window, no mutex).

## 11. Login monitor (event log)

Code: `monitor/mod.rs` (engine, `Supervisor`), `monitor/eventlog.rs` (wevtapi wrappers,
`fetch_status`), `logon.rs` / `ssh.rs` (classification), `xml.rs`, `audit.rs`.

### Classification
* Security log (`logon.rs`, structured XPath query with a server-side `Suppress` for Window
  Manager / Font Driver Host / virtual accounts): a 4624 is a human logon when the LogonType is
  2, 10, 11 or 12 (session) or 7 or 13 (unlock), the TargetUserSid is a real account
  (`S-1-5-21-…` local/AD, `S-1-12-1-…` Entra ID), it is not a virtual account and it was not
  produced by sshd (the OpenSSH monitor reports those, with the client address). The two linked
  4624s of a UAC split-token logon are reported once; the Windows Hello type 11 next to a type 7
  unlock (or type 2 sign-in) is collapsed. 4634 is reported only for sessions that were reported;
  4647 always, without a duplicate 4634. An RDP reconnect (4624 + 4778 for the same account) is
  reported once; a console 4779 that accompanies an RDP takeover is folded into it. 4625 failed
  logons are read for LogonTypes 2, 3, 7, 8, 10, 11, 12 and 13; 1102 (log cleared) becomes a
  security alert; 4719 triggers an audit-policy re-check.
* OpenSSH (`ssh.rs`): only the `payload` field is parsed — `Accepted <method> for <user> from
  <ip> …`, `Failed …`, `Invalid user …`, MaxAuthTries lines (in `OpenSSH/Admin`, read by a second,
  independent subscription), disconnects and post-authentication connection ends; `user: …`
  wrappers and `[preauth]`/`[postauth]` suffixes of newer OpenSSH builds are handled.

### Reading model
* One **pull-mode** subscription per channel (`Security`, `OpenSSH/Operational`, `OpenSSH/Admin`),
  each with its own manual-reset signal event and bookmark file. No callbacks.
* The monitor thread waits on `[ctx.stop, own stop, settings-changed, 3 signals]`. A wake drains
  **only the channels whose signal is set**: reset the event, then `EvtNext` in batches of 32 with
  `NEXT_TIMEOUT_MS` = 1000 ms. After 64 batches in one wake the signal is set again so stop and
  settings changes get a turn.
* `eventlog::fetch_status` maps every `EvtNext` result:

  | `EvtNext` result | `Fetch` | Meaning |
  |---|---|---|
  | TRUE with events | `Events` | handle them |
  | `ERROR_NO_MORE_ITEMS` (259), or TRUE with 0 events | `Drained` | read to the end; wevtapi signals when new records arrive |
  | `ERROR_INVALID_OPERATION` (4317) | `Waiting` | still nothing new since `Drained` — **the normal idle state, not an error** |
  | `ERROR_TIMEOUT` | `Timeout` | batch not finished in 1000 ms; after 3 time-outs in one drain, draining is retried after 60 s |
  | anything else | `Err(code)` | read failure → `Supervisor` |

* Every event goes through `ctx.emit_event` (or `emit_security`); only after that succeeded is the
  in-memory bookmark advanced, and the bookmark is persisted after each batch. A failed emit keeps
  the event, with its cached classification, at the head of a pending queue and retries after 60 s.

### Why 4317 must not be treated as an error
* Once a pull subscription has been read to the end (`ERROR_NO_MORE_ITEMS`, 259), wevtapi answers
  **every** further `EvtNext` with `ERROR_INVALID_OPERATION` (4317) until it sets the signal for
  new records (§15).
* An engine that drains *all* channels whenever *any* signal fires (and right after every reopen)
  and treats 4317 as a broken subscription ends in a reopen spin: reopen → clean first read →
  unsignalled read → 4317 → reopen … on every channel. Measured, that costs 20–27 % of one CPU
  core at idle, with about 1,000 reopens per second.
* Therefore: only signalled channels are drained; 4317 is `Fetch::Waiting`; `EvtNext` has a
  1000 ms budget; the `Supervisor` below guarantees that no failure pattern can spin; the hourly
  bookmark refresh moves the bookmark only when the channel is caught up. The idle service stays
  at 0.00 % CPU, also after test events (§17).

### Failure recovery (`Supervisor`, a pure, unit-tested state machine)
* A read failure reopens the channel **at once at most once per channel per 5 minutes**
  (`IMMEDIATE_REOPEN_PERIOD`; the typical case is an EventLog service restart). Any other failure
  waits for an exponential backoff of **5 s doubling to 10 min**.
* A reopened channel counts as **healthy only after 5 minutes without a failure**
  (`HEALTHY_AFTER`); only then are its failure count and backoff forgotten. One clean read proves
  nothing.
* When **every enabled channel (at least two) failed with the same error code 3 times in a row**
  (`GLOBAL_RESET_AFTER`), all subscriptions are closed and reopened together after a shared backoff
  (fresh wevtapi state), never sooner than any channel's own retry.
* Retries due within 5 s of each other are handled in one wake; the monitor never waits less than
  1 s (`MIN_WAIT`).
* A subscription that is signalled 3 times in a row while its first read finds nothing new
  (`SPURIOUS_WAIT_LIMIT`) is treated as stuck and goes through the same read-failure path.
* `EvtSubscribe` failures retry with the same backoff. An unusable bookmark (15011 / 1168 / 15012:
  log cleared or rolled over) falls back to future events and reports `LOGIN MONITOR GAP`.
* While a channel fails, its monitor state is an error (status screen, tray) and logons are
  reported from WTS session notifications instead.

### Timers (none at all while both monitors are off)
* Every 5 min: EventLog-service watchdog (PID changed or service stopped → resubscribe every open
  channel from its saved bookmark); `sshd_config` check while SSH monitoring is on.
* Every 10 min, and at once on event 4719: audit-policy re-check (`AUDIT POLICY INSUFFICIENT`
  when logon auditing is off).
* Hourly: OpenSSH channel-enabled check and **bookmark refresh**, which moves the saved position to
  the newest record of the channel so that it stays inside the circular log even after days
  without a matching event. It runs only when the channel is caught up (read to the end, nothing
  pending, not stalled); otherwise it is skipped until the next hour.
* One-shot deadlines only after an event: subscription retries, stalled-queue retry (60 s), held
  console disconnects, the failed-login summary, the coalesced history write.

## 12. Chat auto-clean

Code: `telegram/janitor.rs`. Goal: the chats keep only login/logout-type and security alerts;
everything else goes. Everything is kept **per chat**: every paired account has its own private
chat with the bot, and what one user does never deletes anything in another user's chat.

* **`ChatJanitor`**: thread-safe, persistent list of *ephemeral* messages
  (`TrackedMessage {chat_id, message_id, sent_unix, active_unix}`), oldest first, at most 500
  (`MAX_TRACKED`; beyond that the oldest are forgotten, never deleted).
* **Tracked** (only while `auto_clean_chat` is true): every reply the bot sends to a paired user
  (menus, screens, results, confirmations, errors, hints, the pairing reply — an edit keeps the
  message id), every message a paired user sends in their private chat (commands, text, the
  `/pair` message), and delivered `System` notifications in each recipient's chat
  (`is_ephemeral_kind` is true only for `NotificationKind::System`): `VIGIL ONLINE`,
  `VIGIL GOING OFFLINE`, `VIGIL RESUMED`, `FEATURE CHANGED`, `AUDIT POLICY INSUFFICIENT`,
  `LOGIN MONITOR GAP`.
* **Never tracked** (kept forever): `Login`, `Logout`, `FailedLogin` (including
  `FAILED LOGIN ALERTS SUPPRESSED`), `SshLogin`, `SshFailed`, `SshLogout`, `Security` (unauthorized
  access attempts, security log cleared, new account paired, account removed).
* **Deletion paths**
  1. *New message of a user* (`Bot::on_message`): `note_previous` first releases expired
     confirmations, then notes — read-only — the ids of every tracked message of that chat except
     protected ones, and tracks the new message. After the reply went out, `delete_previous` takes
     the noted ids that are still tracked and unprotected and deletes them. Because the first step
     is read-only, a failure while handling the command never makes the old messages permanent.
  2. *Time-based sweep* (`poller::sweep_service`): after `getMe` and after every successful
     `getUpdates` cycle — release expired confirmations, then delete, in every chat, the messages
     whose last activity (`max(sent_unix, active_unix)`) is at least `chat_clean_after_secs` old.
     The long poll wakes the thread at least every ~50 s while online, so there is no extra thread
     or timer; with an empty list the sweep costs one lock.
  3. *`/clear`* (`Bot::clear_chat`, handled before the normal dispatch): take and discard the
     caller's pending confirmation, track the `/clear` message itself, take every tracked message
     of that chat and delete them. No reply. With `auto_clean_chat` false it only answers
     `ui::clear_disabled()`.
* **Button presses** (`keep_alive`) touch the pressed message, so its inactivity timer restarts
  and a menu sent before a restart is tracked from then on. Messages Telegram reports with date 0
  are left alone.
* **Protection**: the message of a pending power confirmation is protected (in memory only, at
  most 24 entries — one per possible account plus a margin) until it is confirmed, cancelled,
  superseded or expired (§7).
* **Telegram limits**: bots cannot delete messages older than 48 hours. Entries whose `sent_unix`
  is 47 hours old (`MAX_DELETE_AGE_SECS`, one hour of margin) are dropped, never sent, and a
  message that old is not tracked at all. `chat_clean_after_secs` is clamped to 60 s … 47 h.
* **`purge`**: per chat, `deleteMessages` with ≤ 100 ids per call (Telegram skips ids it cannot
  delete); `deleteMessage` per id when the server lacks the method (remembered) or refuses a whole
  batch. A retryable failure (network, 429, server error) puts the entries back, in time order, for
  the next sweep; any other failure (e.g. the user blocked the bot) forgets them with a warning.
* **Persistence**: `chat-cleanup.json` = `{version: 1, bot_id, entries}`, written atomically and
  only on change; a corrupt file is renamed to `chat-cleanup.json.corrupt` and the list starts
  empty. `bind_bot(<getMe id>)`: same bot → nothing; no bot recorded → adopt; another bot → forget
  every entry (never delete — the ids may name the new bot's login alerts).
* **Settings**: `auto_clean_chat` (default `true`) and `chat_clean_after_secs` (default `600`),
  read through `AppContext::auto_clean_after() -> Option<u64>` (`None` = off) whenever they are
  needed, so they apply as soon as the service has the changed `settings.json` (settings reload or
  restart).
* **Not covered**: the `⛔ Access denied` replies to strangers (they are not in a paired chat) and
  the messages exchanged by the command line's direct pairing (no janitor runs there) stay.

## 13. Tailscale management

Code: `sys/tailscale.rs`, `sys/session.rs`.

Purpose: Tailscale gives the PC a private, encrypted address on the owner's tailnet that is
reachable from anywhere without port forwarding. `/tailscale up` starts and connects it so the PC
can be reached with Remote Desktop or SSH over its Tailscale address; `/tailscale down` stops it
again, so nothing listens and nothing uses resources. *Run unattended* in the Tailscale app makes
this work before anyone signs in (setup recommends it).

* **Why the app is managed:** on Windows, the tailscaled backend sits in `NoState` until the
  Tailscale app (`tailscale-ipn.exe`, the GUI / tray icon) of a signed-in user connects to it,
  unless Unattended mode is on (§15). So `up` starts the app when it is not running, and `down`
  closes it so that Tailscale is completely off afterwards.
* Only a *bare* `tailscale up` / `tailscale down` is ever run (any flag disables the CLI's "bring
  it up without changing settings" path).
* **`up`** (`up_inner`):
  1. start the `Tailscale` service if it is not running (SCM, 30 s);
  2. if `tailscale-ipn.exe` runs in no session: start the installed app (next to the discovered
     `tailscale.exe`, no arguments) in the active user's session with
     `session::launch_in_session` — user token and environment, `winsta0\default`, no job, no
     inherited handle, not waited for. Nobody signed in → step skipped (ℹ️ "relying on Tailscale
     Unattended mode");
  3. poll the status every 2 s for at most 30 s (`READY_WAIT`) until the backend has left
     `NoState`/`Starting` (while the app is still connecting, a logged-out placeholder without a
     profile also counts as transient);
  4. `Running` → done. `NeedsLogin` without node key and tailnet → refuse (no unowned
     registration from SYSTEM; show the login URL if any). `NeedsMachineAuth` → refuse. Otherwise a
     **bare `tailscale up`** (30 s) as SYSTEM, retried as the session user when the profile refuses
     SYSTEM;
  5. verify for at most 20 s that the state is `Running` (stop early on `NeedsLogin` /
     `NeedsMachineAuth`) and report every step.
* **`down`** (`down_inner`):
  1. bare `tailscale down` (15 s, same owner fallback) while the daemon may run;
  2. `close_app`: every `tailscale-ipn.exe` in any session whose image is
     `<install dir>\tailscale-ipn.exe` is terminated, then waited for (≤ 5 s in total). The check
     (`is_installed_app`) compares the paths textually (case-insensitive, `\\?\` and `/`
     tolerated) and otherwise compares the canonical paths of both, so 8.3 short names
     (`C:\PROGRA~1\TAILSC~1`), junctions and SUBST drives match; anything else is left alone and
     reported;
  3. stop the `Tailscale` service (30 s);
  4. wait ≤ 10 s for `tailscaled.exe` to exit and terminate leftovers;
  5. success = service stopped, no `tailscaled.exe`, app not running.
* **Status**: `tailscale status --json --peers=false` (15 s); `TailscaleStatus.app_running` comes
  from one process snapshot (no CLI call); the Telegram screen shows `App: 🟢 Running` /
  `App: ⚪ Not running`. The tray's refreshes (§10) never start the CLI; setup only reads the
  status.
* **Measured on an installed service:** `down` closed app and service in about 2 s; `up` started
  service and app and reached `Running` in about 6 s. Worst case with every time limit reached:
  about 1–2 minutes.

## 14. Logging and flood protection

Code: `logging.rs`.

* `predator.log` (1 MiB + 1 backup) and `security.log` (1 MiB + 3 backups); every line is
  token-redacted. Security lines are written to both files.
* **Cost of a suppressed line**: the `log_*!` macros first ask `logging::level_enabled` (one
  relaxed atomic load of `MIN_LEVEL`) and only then evaluate their arguments and format them
  (`format_args!` → `log_args`). A line below the configured level (debug without `--verbose`)
  therefore allocates no `String`, takes no lock and does not even evaluate its arguments; a
  message that is a plain literal is passed on without an allocation. `set_min_level` keeps the
  lock-free check and the logger's own level in step.
* **`FloodGuard`** (operational lines only, pure and unit-tested, applied under the logger lock):
  * an identical consecutive line (same level and text) within 60 s (`REPEAT_WINDOW_SECS`) is only
    counted. `… previous message repeated N times` is written when the run ends (a different line
    arrives) or when the line recurs after the window (it is then written again with a fresh
    timestamp). There is no timer, so a run that ends in silence is summarised with the next line;
    a summary written ≥ 2 s after the last repeat adds `(last at <time>)`;
  * at most 200 lines per call site per minute (`SITE_LINES_PER_MINUTE`; the site is the
    `file:line` of the `log_*!` macro, or the text for direct `log` calls), at every level. The
    rest is counted and reported once the minute is over:
    `rate limit: N more line(s) from <site> were not logged in the previous minute (limit 200 per minute)`.
    At most 512 sites are tracked individually; the rest share one bucket;
  * lines below the configured level are dropped before the guard and do not count.
* **Security lines bypass the guard.** A security line first flushes a pending repeat summary so
  the order stays readable. Lines caused by unauthenticated parties go through
  `security_untrusted` (20 per source per hour, 30 per minute overall, §19).

## 15. Platform facts

Measured or verified on Windows 11 (build 26200) unless a bullet names another source. They are
the reasons behind several design decisions above.

**wevtapi pull subscriptions — what does `EvtNext` return when there is nothing new?**
* A fresh subscription can be read at once; its signal event is NOT set initially.
* Reading to the end returns `ERROR_NO_MORE_ITEMS` (259). From then on **every** `EvtNext` fails
  with `ERROR_INVALID_OPERATION` (4317, "The operation identifier is not valid") until wevtapi sets
  the signal event, about 0.5–1 s after a matching record was written. Setting the event yourself
  does not help. After the signal the subscription delivers normally again.
* Identical for `Timeout` 0, 200, 1000 ms and `INFINITE`, and for `EvtSubscribeToFutureEvents` and
  `EvtSubscribeStartAtOldestRecord` (throwaway test program, standard user, `OpenSSH/Operational`).
* A pull subscription never waits for *new* records: 259 comes back at once with 0, 1000 ms and
  `INFINITE`. The timeout only bounds the scan of one batch (a full scan of a 20 MB System log with
  a non-matching filter took 58 ms).
* Consequence: 4317 after 259 is the normal idle state (§11).

**Tailscale for Windows — when does the backend leave `NoState`?**
* Verified on an installed service: the backend sits in `NoState` until the Tailscale app
  (`tailscale-ipn.exe`) of a signed-in user connects, unless Unattended mode is on. A user-less
  node that is not in Unattended mode therefore does *not* report `NeedsLogin`.
* Starting `tailscale-ipn.exe` (no arguments) in the active user's session from the LocalSystem
  service with `session::launch_in_session` works: `/tailscale up` (service start, app start, a
  bare `tailscale up` only if the backend is still not `Running`) reached `Running` in about 6 s.
  `/tailscale down` (bare `down`, terminate the app, stop the service) took about 2 s.

**Telegram Bot API — deleting messages**
* Verified: in a private chat the bot deletes its own messages and the user's messages (commands).
* Telegram does not let bots delete messages older than 48 hours (Bot API documentation); the
  janitor keeps a one-hour margin (47 h).
* As encoded in `telegram/api.rs`: `deleteMessages` takes up to 100 ids per call and skips ids it
  cannot delete; a server without the method (self-hosted, older than Bot API 7.0) needs
  `deleteMessage` per id.
* Design assumption: message ids are only meaningful for the bot that sent or received them, so
  stored ids are never used after a token switch to another bot.

**Wi-Fi SSID with Location services off**
* Verified on an installed service: `/network` showed the SSID through the WinRT path of
  `ssid-helper` (`WlanConnectionProfileDetails.GetConnectedSsid()`) while Windows Location
  services were off.

**Sockets and WinHTTP**
* `shutdown()` on a socket does not wake a thread blocked in `recv` on Windows. The direct client
  therefore puts its sockets in non-blocking mode with `WSAEventSelect` and waits on an event that
  `interrupt()` can set as well (§16).
* WinHTTP runs its own worker thread pool for an open session, even when the only traffic is one
  long poll. Profiling a WinHTTP-based build of the idle service showed that pool causing about
  95 % of the process's wake-ups and about 1 MB of its private memory (§17).

## 16. HTTPS transport

Files: `net/http.rs` (facade `HttpClient`, `HttpError`, `HttpResponse`, `Interruptible`, backend
`Selector`), `net/direct.rs` (direct client: pool, sockets, TLS), `net/http1.rs` (HTTP/1.1
request head and response parsing, pure), `net/proxy.rs` (start decision from the environment
and the registry, pure parts unit-tested), `net/winhttp.rs` (WinHTTP client; re-exports the
facade types). `TelegramApi` owns one `HttpClient`, created with the token, shared by the poller,
the sender, bot replies and the offline send.

### Backend choice at creation (`proxy::initial_choice`)
Read once per `HttpClient` (i.e. at service start and when a new token is loaded), from the
registry only — no WinHTTP call, so `winhttp.dll` stays unloaded:

| Condition | Start on | Automatic switching |
|---|---|---|
| `PREDATOR_HTTP_TRANSPORT=direct` | direct | none (for diagnostics) |
| `PREDATOR_HTTP_TRANSPORT=winhttp` | WinHTTP, `DEFAULT_PROXY` mode (`AUTOMATIC_PROXY` when only the Internet Settings name a proxy/PAC) | never back to direct; `DEFAULT_PROXY` may still move to `AUTOMATIC_PROXY` |
| a static WinHTTP proxy in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings` (`netsh winhttp set proxy`) | WinHTTP, `DEFAULT_PROXY` | may move to `AUTOMATIC_PROXY` |
| a manual proxy or PAC URL in the Internet Settings that apply to the process: `HKCU` (for the service: LocalSystem's own hive), or `HKLM` when the policy `ProxySettingsPerUser = 0` makes them machine-wide; binary `DefaultConnectionSettings` or the plain `ProxyEnable`+`ProxyServer` / `AutoConfigURL` values | WinHTTP, `AUTOMATIC_PROXY` | none (last step) |
| anything else | direct | may move to WinHTTP `AUTOMATIC_PROXY` |

`auto` or an empty value means "not set"; values are trimmed and case-insensitive; any other
value is ignored with a warning. "Automatically detect settings" (WPAD) alone does not count —
it is on almost everywhere; the run-time fallback covers networks that need it. The decision is
logged: `HTTPS transport: <name> (<reason>)` at INFO when WinHTTP was chosen, at DEBUG for direct,
and `Telegram bot token loaded (HTTP transport: <name>)` at INFO in either case.

### Run-time fallback (`Selector`, pure, unit-tested)
* The backend changes only when another one is *shown* to work. A connect-level failure of the
  current backend (direct: name resolution, TCP connect, TLS handshake incl. certificate; WinHTTP:
  any network error or time-out) is counted, unless Windows reports no network at all
  (`InternetStatus::Disconnected`). A request that reaches the server resets the count, the
  streak and the trial gap (direct: any HTTP response, or a failure after the TLS handshake;
  WinHTTP: any HTTP response). Local problems and cancelled requests neither count nor reset.
* After `TRIAL_FIRST` = 3 counted failures spanning at least `TRIAL_MIN_SPAN` = 60 s, the next
  request is sent once through WinHTTP with `AUTOMATIC_PROXY` (WPAD / PAC / Internet Settings).
  Only one trial runs at a time; other requests keep using the current backend meanwhile.
* Trial reached Telegram while the current backend kept failing → switch to WinHTTP
  `AUTOMATIC_PROXY` for the rest of the process (`log_warn!`: `HTTPS: the direct connection to
  the server kept failing while WinHTTP with automatic proxy detection reached it; using WinHTTP
  (system proxy support) until the service restarts`); the direct pool's idle connections are
  closed. From WinHTTP `DEFAULT_PROXY` the warning is `HTTPS: WinHTTP with the default proxy
  setting kept failing while automatic proxy detection (WPAD/PAC) reached the server; using it
  until the service restarts`. "For the rest of the process" means until the service restarts or
  a new token creates a new `HttpClient`.
* Trial reached Telegram, but so did the current backend meanwhile → nothing changes
  (`TrialNotNeeded`, DEBUG).
* Trial failed (or was inconclusive) → keep the backend, close the trial's WinHTTP session, and
  wait for twice as many failures before the next trial: 3, then 6, 12, 24, 48, 48 … (`TRIAL_MAX`)
  (`log_info!`: `… did not reach the server either; keeping the current connection method (next
  check after N more connection failures)`).
* So an ordinary outage (ISP or DNS down while Windows still reports a network) never moves the
  service onto WinHTTP for good: the trial fails like everything else.
* Not trialled: `direct` forced by the environment, and WinHTTP `AUTOMATIC_PROXY` (last step).
* The WinHTTP client of a mode is created on first use (`winhttp.dll` is delay-loaded, so it is
  mapped only then). A delay-loaded DLL stays mapped after a failed trial, but its session (and
  the session's worker threads) is closed.

### Direct client (`DirectClient`, `Engine<TlsDialer>`)
* **Connect:** `ToSocketAddrs` (at most 8 addresses), `TcpStream::connect_timeout` per address
  (15 s each, 30 s in total), `TCP_NODELAY`, then the socket goes non-blocking with
  `WSAEventSelect(FD_READ | FD_WRITE | FD_CLOSE)` on a per-connection manual-reset event. Every
  read/write that would block waits on that event with the phase deadline.
* **TLS:** one SChannel credential for all connections, acquired on first use (TLS 1.2 + 1.3;
  TLS 1.2 alone if the system refuses the mask), `Builder::domain(host)` → chain and name
  validation (§19). Handshake limit 15 s.
* **HTTP/1.1:** `POST` with `Host`, `User-Agent`, `Content-Type: application/json`,
  `Content-Length`, `Connection: keep-alive`; bodies ≤ 16 KiB go in the same TLS write as the head.
  Responses: `Content-Length`, `chunked` (extensions and trailers accepted) or read-to-close
  (capped); 1xx skipped; reusable only for HTTP/1.1 without `Connection: close` and a
  self-delimited body read to the end.
* **Time limits:** connect 15 s per address / 30 s total, handshake 15 s, send 15 s, all capped at
  the caller's `timeout`, which bounds the receive phase (long poll: 50 + 15 = 65 s; most other
  calls 20 s, callback answers 10 s; the offline send at stop 3 s).
* **Pool:** at most `MAX_IDLE` = 3 idle connections, most recently used first, one per concurrent
  request (the long poll and the sender/bot replies run on different threads). An idle connection
  is dropped when it is older than `IDLE_LIMIT` = 30 s, older than the last interrupt, was marked
  `Connection: close`, or fails the reuse check (a non-blocking `peek`: closed by the server, or
  unexpected bytes such as a TLS alert). Connections are closed outside the pool lock.
* **Retry:** exactly once, on a fresh connection, and only when a *reused* connection failed before
  any response byte arrived (the "server closed the idle connection" race) and the failure was not
  a time-out (the time budget is spent) or a protocol error. Logged at DEBUG.
* **Interrupt (`interrupt()`):** bumps the pool generation, sets the cancel flag of every request in
  flight and signals its event, and closes the idle connections. `CancelCtl::should_stop` =
  cancelled and (`Interruptible::Always` or not yet completely sent). Only the carrying thread
  marks a request as sent, so a cancel that arrives after the last byte was written can never abort
  an `UntilSent` request; a complete response is returned even if the interrupt came just after
  it. A cancelled request fails with `HttpError::Network { code: 995, … }` (phase `Cancelled`,
  neutral for the selector). Interrupted connections are never pooled again.
* **Errors:** every failure carries a `Phase` (`Local`, `Resolve`, `Connect`, `Tls`, `Exchange`,
  `Cancelled`) for the selector, and an `HttpError` whose text never contains host or path (§19).
  Typical texts: `cannot resolve the server name: …`, `cannot connect to the server: …`,
  `server certificate rejected: …`, `TLS handshake failed: …`, `receiving the response failed: …`,
  `the server closed the connection without a response`, `request timed out`.
* **Panics** inside dialing or a round trip are caught; they fail that request only.

### WinHTTP fallback (`WinHttpClient`)
Synchronous WinHTTP; one session at a time (for the mode in use), shared by all threads; every
handle in an RAII guard and never closed from another thread. TLS 1.2/1.3, session-local
connection pooling, HTTP/2 when offered, cookies and redirects disabled; resolve/connect/send
limits 10/15/15 s capped at the caller's timeout. `interrupt()` has no effect on this backend: a
long poll on a dead connection ends at its 65 s receive limit.

### Diagnostics
`HttpClient::transport_name()` → `direct (SChannel)`, `WinHTTP (default proxy)` or
`WinHTTP (automatic proxy)`. Shown by `predator-service status` (`HTTPS transport:`, from the
running service over IPC), by `selftest` (`Telegram HTTP transport:`, the CLI's own client, §8)
and in `predator.log` (start decision, switch, failed trials). `DirectClient` also counts the
connections opened and reused (used by the live tests).

### Tests
Unit tests cover the selector rules, the start decision and registry-blob parsing, HTTP/1.1
parsing and framing, the pool (reuse, limits, interrupt generations, retry rule) with mock
dialers, the interrupt policies on local sockets, and that no error text contains the token or the
host. Live checks (`#[ignore]`, no token; `scripts\test.ps1 -Ignored` or
`cargo test --lib net::direct -- --ignored`): two requests on one pooled connection to
`api.telegram.org`, rejected badssl.com certificates, both interrupt policies against a slow
httpbin.org response, and TLS 1.3-only and TLS 1.2-only handshakes with the Bot API.

## 17. Resource footprint

### Measured idle footprint
Measured on a Windows 11 x64 PC, both services idle, both monitors on:

| Process | Private bytes | Working set | Wake-ups | CPU | Handles |
|---|---|---|---|---|---|
| `predator-service.exe` | ≈ 2.4 MB | ≈ 3.3 MB (avg) | ≈ 5 per minute | ≈ 18.5 M cycles per 10 min (effectively 0 %) | ≈ 245 |
| `predator-tray.exe` | | | ≈ 5.7 per minute | | |

`scripts/measure.ps1` samples CPU time, private bytes, working set, threads and handles of the
installed service and tray (read-only; it changes nothing).

### Where idle cost comes from
Vigil's own threads block in the kernel (§2). In a WinHTTP-based build the largest idle cost
was WinHTTP's own worker thread pool — about 95 % of the process's idle wake-ups and about 1 MB of
private memory (§15). The largest lever was therefore to take WinHTTP off the normal path; the
remaining techniques remove smaller, steady costs.

### Techniques

| Area | Technique | Code |
|---|---|---|
| Design | Event-driven everywhere: pull-mode event-log subscriptions with bookmarks, SCM / connectivity notifications, one long poll; no polling loops | §2, §11; `monitor/`, `net/connectivity.rs` |
| HTTPS | Direct TcpStream + SChannel client with HTTP/1.1 keep-alive; WinHTTP only as the proxy fallback; `winhttp.dll` delay-loaded | §16; `net/` |
| Long poll | Interrupted on a real connectivity change or resume (`getUpdates` always; other calls only until sent) | §8; `Shared::interrupt_long_poll` |
| CPU | EcoQoS: `SetProcessInformation(ProcessPowerThrottling)` with `PROCESS_POWER_THROTTLING_EXECUTION_SPEED` in both masks at start; switched off (still controlled, state 0) at the start of the stop sequence, which has a hard time budget | `util::win::set_eco_qos`; `Runtime::start` / `shutdown` |
| Memory | `TrimPolicy` (pure, unit-tested) + `Shared::maybe_trim`: `HeapSetInformation(NULL, HeapOptimizeResources)` (release heap caches, Windows 8.1+), then `SetProcessWorkingSetSizeEx(-1, -1)` | `service/runtime.rs`, `util::win` |
| Queue | Coalesced acks and delivery marks; synchronous, durable pushes; buffer shrink after bursts | `notify/queue.rs`, `service/sender.rs` |
| Logging | Level check before formatting | §14; `logging.rs` |
| Tray | `ImmDisableIME`; SCM notifications instead of a polling timer; 5 min safety refresh; `ipc::request_to_pid`; pairing check only while its own code is active | §10; `tray/` |
| Build | `opt-level = "z"`, fat LTO, `codegen-units = 1`; delay-loaded DLLs; static CRT; the embedded tray stays in the read-only data section | §18; `Cargo.toml`, `build.rs` |

### Working-set trim rules (`TrimPolicy`)
* Consulted only at quiet points of the poller loop — after a `getUpdates` cycle that returned no
  updates, or (start-up trim only) from the poller's idle wait while there is no usable token —
  so it needs no timer.
* **Start-up trim** (`TrimKind::Startup`): once, when the runtime is at least
  `STARTUP_TRIM_DELAY` = 60 s old and the last activity is at least `BURST_QUIET` = 30 s old. With
  a token this happens at the first quiet cycle after that (i.e. after the first successful
  getUpdates). After the start-up short poll the first 50 s long poll ends before the 60 s mark,
  so this is usually the second one, about 100 s after the start; while Telegram is unreachable
  the trim waits until it answers. Without a usable token the idle wait ends once at the due
  time to do it. Most of the start-up working set are pages of DLLs and code used only while
  starting (measured on an installed service: about 13.7 MB → 3–5 MB).
* **Burst trim** (`TrimKind::AfterBurst`): only when there was activity since the last trim, the
  last activity is at least 30 s old and the last trim at least `MIN_TRIM_INTERVAL` = 10 min ago.
  Activity = handled updates (poller), deliveries (sender), and a Tailscale status refreshed
  within the last 2 minutes (Tailscale workers, IPC). An idle service is never trimmed again.
* Why never periodic: a trim frees nothing, it moves pages to the standby/modified lists; pages
  that are touched again come back by (usually soft) fault. Trimming on a period would only buy
  fault churn. The heap-cache release before the trim is the part that can lower committed
  (private) memory: the heaps drop their cached free blocks and decommit what they can.
* Skipped while stopping; logged at DEBUG only (with before/after private and working-set sizes
  when debug logging is on).

### Coalesced queue writes (`NotificationQueue`)
* `push` writes `queue.json` atomically before it returns (before the monitor advances its
  bookmark).
* `ack` removes the item and records its dedupe key in memory at once; `mark_delivered` records a
  recipient in the item's `delivered_to` (bounded at 64 ids). The file is rewritten only when
  `ack_write_due`: the queue became empty (acks only), nothing was written since open, or the last
  write is at least `ACK_WRITE_INTERVAL` = 2 s old. Otherwise the change rides on the next due
  write, push or `flush`. The sender calls `flush` before every wait; the runtime calls it at stop.
* Effect: draining an N-item backlog costs about one write per 2 s; rewriting the whole file on
  every ack would cost N full rewrites (O(N²) bytes in total).
* Consequence: after a crash or power loss, items (or recipients) acknowledged since the last write
  are delivered again after the restart. Still at-least-once per recipient; nothing is lost.
* `shrunk_capacity`: after removals, a `VecDeque` with more than 64 slots that is less than a
  quarter full shrinks to twice its length (at least 16), with hysteresis so a fluctuating queue
  does not reallocate on every ack.

### Alternatives considered

| Idea | Evidence | Decision |
|---|---|---|
| Segment Heap | No gain at idle, slightly worse | Default process heap kept |
| mimalloc as global allocator | Worse: the system DLLs the service loads allocate from the process heap anyway, so a second allocator adds its own overhead on top | Not used |
| `panic = "abort"` | Would remove crash isolation: `spawn_supervised` and the `catch_unwind` wrappers (§5) restart a failed thread or feature instead of losing the whole service | `panic = "unwind"` kept |
| Thread-pool rewrite of the service threads | ≈ 40 KB per thread; not worth rewriting working, tested code | Not done |
| Lower memory priority for the service process | No effect | Not used |
| WinHTTP keep-alive / worker tweaks | No effect on the thread pool's wake-ups or memory | Direct transport on the normal path instead |

## 18. Assets and build

* **Icons**: `examples/icongen.rs` renders an original Vigil logo (anti-aliased vector shapes,
  no external art) to `assets/predator.ico` (16,20,24,32,40,48,64,128,256; PNG-compressed frames
  via `miniz_oxide`, a dev-dependency only) and `assets/predator-off.ico` (greyscale + red status
  dot; 16–48).
* **Resources**: `build.rs` writes `.res` files directly (RT_ICON/RT_GROUP_ICON, RT_VERSION,
  RT_MANIFEST — no rc.exe) and links them with `cargo:rustc-link-arg-bin=<bin>=<path.res>`. A
  missing icon only produces a warning (so `icongen` can bootstrap); a corrupt one is an error.
* **Linker options for `predator-service`**: `/DELAYLOAD:<dll>` for the 11 DLLs in
  `DELAY_LOAD_DLLS` (§1), `/IGNORE:4199` (a delay-loaded DLL without imports in a test harness is
  informational only), `/DEPENDENTLOADFLAG:0x800` (§9) and `delayimp.lib`.
* **`embed-tray`** feature: see §9. `build.rs` re-runs when `PREDATOR_EMBED_TRAY` or the tray
  file changes.
* **Release profile** (`Cargo.toml`): `opt-level = "z"` (measured smaller than `"s"`: about
  232 KB less service image and 0.2 MB less working set; the service is I/O bound, so the slower
  code paths do not matter), fat LTO, `codegen-units = 1`, `strip = true`, no debug info,
  `incremental = false`, and `panic = "unwind"` on purpose (crash isolation, §5 and §17).
  `.cargo/config.toml` links the C runtime statically (`+crt-static`), so neither executable needs
  `VCRUNTIME140.dll`; the Universal CRT ships with Windows 10/11.
* **Toolchain**: Windows 10/11 x64, Rust stable with the MSVC target (1.88 or newer), Visual
  Studio Build Tools with "Desktop development with C++" (MSVC + Windows SDK).
* **`scripts/build.ps1`** (`-OutDir DIR`, `-SkipChecks`; honours `CARGO_TARGET_DIR`): runs, in
  order, `cargo fmt --all -- --check`, `cargo check --all-targets`, `cargo test --all-targets`,
  `cargo clippy --all-targets -- -D warnings` (skipped with `-SkipChecks`), then
  `cargo build --release --target x86_64-pc-windows-msvc --bin predator-tray` and
  `cargo build --release --target x86_64-pc-windows-msvc --bin predator-service --features
  embed-tray` with `PREDATOR_EMBED_TRAY` set to that tray. It writes `dist\` (default; a different
  `-OutDir` must be a plain, empty or previously generated folder):
  `Vigil.exe`, `README.md`, `LICENSE` and `SHA256SUMS.txt`, and verifies the
  result: `version` prints the Cargo version, `help` works, and the tray written by the hidden
  `extract-tray` diagnostic is byte-identical to the tray that was built. Nothing is installed.
* **`scripts/test.ps1`** runs the tests (`-Ignored` adds the live `#[ignore]` tests);
  **`scripts/measure.ps1`** measures the installed processes (§17).
* **CI**: `.github/workflows/ci.yml` runs `scripts/build.ps1` on `windows-latest` for pushes to
  `main` and pull requests and uploads the exe and `SHA256SUMS.txt`;
  `.github/workflows/release.yml` builds tags `v*`, checks that the version matches the tag and
  publishes the GitHub release.

## 19. Security review

Summary of the threat-model decisions behind the code. Attackers considered: Telegram accounts
that are not paired and anyone who learns the bot token; standard (non-admin) local accounts and
their processes, including the tray owner's own non-elevated processes; the network (the service
listens on no socket; it only makes outbound HTTPS requests, through its own SChannel client or,
behind a proxy, through WinHTTP, §16); planted files next to the downloaded release file. Out of
scope: local administrators (they can always run code as SYSTEM), a compromised Telegram account
of a paired user, and Telegram itself.

### Data-directory trust
* `%ProgramData%` lets every standard user create sub-folders, and any account can create a
  machine-scope DPAPI blob with the (public) entropy. A pre-created `Vigil` folder could
  therefore carry a forged `token.dat`, an attacker's Telegram accounts in `settings.json` or a
  poisoned `audit-backup.json`.
* Rule (`winsec::assess_data_dir`): the root is trusted only when SYSTEM or Administrators own it,
  its DACL is protected, and it grants access to nobody but SYSTEM, Administrators (and OWNER
  RIGHTS). Every file and folder inside must be owned by SYSTEM, Administrators, an
  `NT SERVICE\*` SID or the administrator running setup, grant nobody else access, and must not be
  a junction or symbolic link.
* Setup and `install` move an untrusted folder to `Vigil.untrusted-YYYYMMDD-HHMMSS` without
  reading it, create a new one atomically with `DATA_DIR_SDDL` (`CreateDirectoryW` with a
  security descriptor), so there is never a moment with the inherited, user-writable ACL,
  re-secure it strictly (every child it cannot reset is fatal; junctions are removed, not
  followed) and check it again.
* CLI commands that write to the default directory (`set-token`, `set-owner`, `set-owner-sid`,
  `features`, the direct `pair` path, `users remove` without a service, `audit enable`, setup's
  token and account steps) go through `DataCtx::ensure()`, which refuses an untrusted root and
  creates a missing one atomically. Setup keeps a stored token or accounts only from a trusted
  folder. `uninstall` never applies an `audit-backup.json` from an untrusted directory or with a
  foreign ACL.
* Residual risk: at start the service only re-applies the ACL (`secure_data_dir(root, true)`,
  which takes ownership of what is inside); it does not run the trust check. If an administrator
  deletes the folder while the service stays installed, a standard user could pre-create it
  before the next start. Recovery is to run setup again, not to re-create the folder by hand.

### Program folder and binaries
* A LocalSystem service binary must not be modifiable by non-admins. Setup creates
  `<ProgramFilesDir>\Predator` atomically with `INSTALL_DIR_SDDL` or takes an existing Vigil
  folder over (owner Administrators + protected DACL), refuses system folders, junctions and
  folders of other programs, and verifies the result (§9). The Program Files location comes from
  HKLM, which only administrators can change.
* Files are written as `.new-<hex>` inside the protected folder (so they get its ACL), read back
  and compared by SHA-256 with the image in memory, and only then renamed into place. The tray
  image is checked against the SHA-256 recorded at build time. Loadable modules next to the
  executables are removed.
* `install::check_program_files` independently refuses to register (or update) the service when
  its folder or executables can be written by non-admins or when loadable modules
  (`.dll/.ocx/.cpl/.local/.manifest`) sit next to the exe.
* Setup installs the bytes of the file it was started from; the release is not code-signed, so
  the download should be checked against `SHA256SUMS.txt` (README).

### Setup and DLL planting
* DLL search restricted to System32 for on-demand loads (`SetDefaultDllDirectories`) and for the
  static imports (`/DEPENDENTLOADFLAG:0x800`); `shell32` delay-loaded and used only by setup (§9).
* The elevated relaunch passes only `setup`, `--invoking-sid`, an absolute `--token-file` path,
  `--telegram-id`, `--yes` and `--verbose`; the elevated side validates the SID (never
  LocalSystem). The token never appears on a command line.
* The elevated setup starts the tray and browser links only through the signed-in user's own shell
  (`explorer.exe`), never elevated; it stops only `predator-tray.exe` processes whose image is
  exactly the installed tray, checked on the same process handle that is terminated.

### Token scope
* Decision: machine-scope DPAPI blob, protected by the file ACL (SYSTEM + Administrators), no
  migration at service start. Protecting it for LocalSystem only would add no protection against
  administrators, who can run code as SYSTEM, and it would lock elevated administrators out of the
  direct pairing path and `selftest`.
* Consequence: any process that can read `token.dat` on this PC can decrypt it, so the
  data-directory trust rule is what guarantees the file was written by an administrator. The blob
  is useless on another PC. The token is never passed on a command line (hidden prompt, stdin or a
  file path), never written in plain text, and log lines are redacted.
* A user-scope (`U`) blob still loads in the service; the direct `pair` path detects it and asks
  for the token again (`set-token`), and setup asks for a new token when the stored one cannot be
  read. `secrets::migrate_to_machine_scope` exists but is not called automatically.

### IPC authorization
* Transport: the DACL denies network logons and gives interactive users read/write without the
  right to create pipe instances, and the service creates the first instance, so while it runs
  nobody else can serve the name; remote clients are rejected. Because another process could
  create the name while the service is stopped, clients verify the server PID against the SCM
  (anti squatting).
* Every request is authorized by impersonating the client at identification level:

  | Caller | Allowed |
  |---|---|
  | LocalSystem, elevated member of Administrators | every request |
  | the configured tray owner SID (unelevated) | `Status`, `SetFeature`, `TailscaleStatus`, `RestartService`, `ReloadSettings`, `StartPairing` with `admin: false`, `PairingStatus`, `CancelPairing`, `ListUsers` |
  | anyone else | nothing (`Denied`) |

  Admin pairing codes and `RemoveUser` need a privileged caller because every unelevated process
  of the owner's session carries the owner SID, not only the tray.
* The request set is closed. The only inputs are a feature key and state, a code lifetime (clamped
  to 60 … 3600 s) and role flag, and a numeric user id; `ReloadSettings` merely re-reads the
  admin-only `settings.json`. A pairing code travels only in the reply to the caller that created
  it.
* Residual risk (by design): a non-elevated process of the tray owner can create a User-role
  pairing code and so add a Telegram account. Such an account can use every command except
  removing accounts. Mitigations: every paired account is told at once
  (`NEW TELEGRAM USER PAIRED`, kept in the chat), admins can remove it immediately (`/users`),
  and the security log records who created the code. The owner's processes can also cancel an
  active code (denial of service only).
* Denial of service: a silent client is dropped after 1.5 s, requests are limited to 4 KiB,
  denials and quick requests are answered on the accept thread, and only authorized slow requests
  use one of at most two workers (otherwise a "busy" error).
* Log flooding: denial lines go through `security_untrusted` — 20 lines per source per hour, 30
  per minute overall, at most 256 tracked sources (the rest share one bucket); suppressed lines are
  counted and summarized when their window ends. `security.log` keeps three 1 MiB backups.
* Telegram-side denials use the same limiter: unauthorized messages and button presses are logged
  with source `tg:<user id>`, non-private chats and sender-less messages with `tg-chat:<chat id>`.
  Lines caused by paired users, an administrator or the service itself (feature changes,
  lock/logout/power/Tailscale requests, pairing, removals, settings reloads) use the unlimited
  `logging::security`. The operational log has its own flood guard (§14).

### Telegram authorization and replay
* At most 20 accounts, identified by numeric id; private chat with `chat.id == from.id`;
  usernames never trusted; groups and channels are left at once; edited messages never execute.
* From Telegram, accounts are added only with a one-time code created on the PC (§6); an
  administrator on the PC can also authorize an id directly (`setup --telegram-id`, `set-owner`).
  Pairing attempts are the only input processed before authorization, and every failure looks
  exactly like any other denial.
* Messages carry a date: state-changing commands older than 300 s are refused (stale rule).
* Button presses carry no date: presses delivered from Telegram's backlog (first batch after start
  or bot change, or after a > 90 s gap) never execute state-changing actions, including removing
  an account, and a backlogged confirmation is discarded (§7). This closes the "pressed Shutdown
  yesterday, PC comes online today" case.
* Confirmations: one pending entry per user, random one-time nonce (16 bytes from
  `BCryptGenRandom`), taken atomically from the user's own entry only, 60 s lifetime, Power
  Management re-checked at confirm time, and refused when the account was removed or paired again
  after the dialog was created.
* At-most-once execution: the update id is persisted (with the bot id) before dispatch; a position
  recorded for another bot is discarded instead of being applied to the new bot's update ids.

### Pairing codes
* 10⁸ possible codes, one active at a time, single use, 60 … 3600 s lifetime (600 s by default).
  After 5 wrong guesses in total the code is invalidated, so an attacker's chance per code is at
  most 5 in 10⁸; each sender additionally gets at most 5 wrong guesses per hour across codes, and
  a blocked sender cannot burn the code of a legitimate user.
* Constant-time comparison; malformed input is no guess; codes are memory-only, never logged,
  never sent to Telegram; the code text is hidden in log lines and alerts even for wrong guesses.
* Admin codes require an elevated administrator on the PC; the first account of an empty list is
  an Admin so the list can always be managed; the last Admin cannot be removed.

### HTTPS transport (direct SChannel client and WinHTTP fallback, §16)
* **Validation always on.** The direct client uses one SChannel credential (TLS 1.2 + 1.3 via
  `SCH_CREDENTIALS`; TLS 1.2 only when the system refuses the combined mask) and sets the expected
  host name (`tls_stream::Builder::domain`), so the `schannel` crate validates the certificate
  chain against the Windows trust store and the name. There is no code path, option, environment
  variable or setting that skips it. Certificate failures are reported as `server certificate
  rejected: …` (phase TLS); live tests check that `wrong.host`, `expired`, `self-signed` and
  `untrusted-root` badssl.com hosts are refused. The WinHTTP fallback uses `WINHTTP_FLAG_SECURE`,
  TLS 1.2/1.3, never sets a `SECURITY_FLAG_IGNORE_*` option, and disables cookies and redirects.
* **The token never reaches an error or a log line.** It is part of the request path. Transport
  errors are built from the error code (system message table) or the error kind plus fixed text
  (`net::http::io_error`), never from the host, the path or an `io::Error`'s own text; nothing in
  `http1.rs` formats the request target into an error. `TelegramApi` additionally scrubs the token
  from every error text (defence in depth), and `HttpClient`/`DirectClient` print only
  `{ .. }` in `Debug`. Unit tests assert that error texts contain neither the token nor the host.
* **Plaintext buffers.** The request head (and a body up to 16 KiB, sent in the same TLS write) is
  built in a per-connection buffer that is overwritten with zeros right after the write
  (`wipe`), before it can be reused; per-connection buffers that grew above 64 KiB are released
  after the request.
* **Input and output bounds.** Host and path are validated before anything is sent (host:
  `[A-Za-z0-9.-]`, ≤ 253 bytes; path: visible ASCII, ≤ 8 KiB), the User-Agent is sanitised, so no
  header can be injected. Replies are limited to 16 KiB of head (and of chunked trailers), 4 KiB
  per chunk-size line, 8 interim 1xx responses and 4 MiB of body; a `101` switch is refused.
* **Proxies.** Through a proxy (WinHTTP), HTTPS runs in a CONNECT tunnel, so the proxy sees the
  host name only. A TLS-inspecting proxy whose root certificate this PC trusts can read the
  traffic, token included; that is the administrator's decision and outside this threat model.
  WinHTTP's automatic proxy mode (WPAD / PAC / Internet Settings) is used only when the Internet
  Settings that apply to the service name a proxy or PAC script, for a trial request, or after a
  switch (§16). A rogue WPAD or PAC answer on the local network can at worst route the traffic
  through a proxy, which still only sees a validated TLS tunnel.
* **Who can choose the transport.** The service reads `PREDATOR_HTTP_TRANSPORT` from its own
  environment (the system environment plus the service's `Environment` registry value) and the
  proxy configuration from `HKLM` and LocalSystem's own `HKCU` (`HKU\S-1-5-18`). With the default
  Windows ACLs all of these are writable only by SYSTEM and Administrators, so a standard user
  cannot redirect the service's traffic.

### Child processes
* Fixed allowlist (§5), no shell, no program path or argument from Telegram. `SPAWN_LOCK`
  serializes every spawn so pipe handles made inheritable for one child can never leak into
  another. Children with captured output run in a kill-on-close job with a hard timeout; a child
  started in another session (`CreateProcessAsUserW`, started suspended, then assigned, then
  resumed) runs without the job when Windows refuses the cross-session assignment, and a timeout
  then terminates only that process.
* The SSID lookup runs in `ssid-helper` so that COM/WinRT/WLAN code never runs inside the
  LocalSystem service; a crash there only costs the SSID line.
* The Tailscale app is started only from the installed path (`tailscale-ipn.exe` next to the
  discovered `tailscale.exe`, an absolute path that must exist), with no arguments, with the
  session user's token and environment (never SYSTEM's), on `winsta0\default`, inheriting no
  handle. `down` terminates a `tailscale-ipn.exe` only after checking, on the same process handle
  (so a reused PID cannot be hit), that its image is `<install dir>\tailscale-ipn.exe`; PIDs 0 and
  4 are refused.

### Untrusted text
* Names, usernames, host names, failure reasons and message excerpts chosen by others are
  truncated and cleaned before they reach a message: `esc` replaces control characters with
  spaces (no injected lines), removes bidirectional-text controls (LRM/RLM, embeddings, overrides,
  isolates, ALM — a name cannot visually reorder its line, e.g. the numeric id in `/users`) and
  HTML-escapes the rest. Stored display names are cleaned the same way (`clean_user_name`); log
  lines replace control characters and quotes (`sanitize`); values that cross the pipe are reduced
  to one line before the tray or console shows them (`ipc::one_line`).

### Chat cleanup
* Only ids are stored (`chat-cleanup.json`, admin-only data folder). Only messages of paired
  users' private chats are tracked: strangers, groups and the `Access denied` replies never feed
  the janitor. The list is bound to the bot id, so a token switch can never make the service
  delete the new bot's messages (e.g. login alerts) that happen to reuse an old id: entries of
  another bot are forgotten, never deleted.
* Login, logout, failed-login (incl. the suppression summary), SSH and `Security` alerts (incl.
  new and removed accounts) are never tracked, so neither a setting nor `/clear` nor the
  time-based sweep can delete them.
