# Troubleshooting

Most problems are fixed from the **management menu**. Start `PredatorRemoteController.exe` again
(or the installed copy, `C:\Program Files\Predator\predator-service.exe`, without arguments),
confirm the Windows prompt (User Account Control), and the menu opens:

```
Predator Remote Controller 1.0.0 - installed
  Service: Running | Bot: @YourPcBot | Telegram users: 2
  Installed in C:\Program Files\Predator (version 1.0.0)

  1  Status
  2  Pair a Telegram user
  3  Telegram users (list / remove)
  4  Change bot token
  6  Open the bot in Telegram
  7  Uninstall
  0  Exit
```

Option `5  Update installed program to this version (…)` appears only when the file you started
differs from the installed one (see [Updating to a new version](#updating-to-a-new-version)).

The commands in this guide use the installed copy from an **elevated PowerShell** (right-click →
*Run as administrator*) unless a step says otherwise. The data folder `%ProgramData%\Predator` is
readable only by SYSTEM and Administrators. To keep the commands short:

```powershell
$exe  = "C:\Program Files\Predator\predator-service.exe"
$data = "$env:ProgramData\Predator"
& $exe help       # every command and option
```

## Contents

- [First steps: status, selftest, logs](#first-steps-status-selftest-logs)
- [Download and setup](#download-and-setup)
  - ["Windows protected your PC" (SmartScreen)](#windows-protected-your-pc-smartscreen)
  - [Antivirus quarantined or blocked the program](#antivirus-quarantined-or-blocked-the-program)
  - [The UAC prompt was declined](#the-uac-prompt-was-declined)
  - [Setup messages](#setup-messages)
- [Service does not start](#service-does-not-start)
- [Bot token revoked, changed or invalid (401 Unauthorized)](#bot-token-revoked-changed-or-invalid-401-unauthorized)
- [The bot does not answer](#the-bot-does-not-answer)
- [Pairing code does not work](#pairing-code-does-not-work)
- [`pair` or `users remove` is refused on the PC](#pair-or-users-remove-is-refused-on-the-pc)
- [A second user gets no alerts](#a-second-user-gets-no-alerts)
- [409 Conflict](#409-conflict)
- [Behind a proxy / Telegram unreachable — force WinHTTP](#proxy)
- [How to see which HTTPS transport is used](#how-to-see-which-https-transport-is-used)
- [No Windows login alerts](#no-windows-login-alerts)
- [No SSH alerts](#no-ssh-alerts)
- [Network and battery screens](#network-and-battery-screens)
- [Remote Desktop and SSH over Tailscale](#remote-desktop-and-ssh-over-tailscale)
- [Tailscale errors](#tailscale-errors)
- [Tailscale app not running / stuck in NoState](#tailscale-app-not-running--stuck-in-nostate)
- [Old bot messages are not deleted](#old-bot-messages-are-not-deleted)
- [Tray icon is hidden or missing](#tray-icon-is-hidden-or-missing)
- [Queue and offline behaviour](#queue-and-offline-behaviour)
- [Wrong times in messages (time zone)](#wrong-times-in-messages-time-zone)
- [Power actions fail or are refused](#power-actions-fail-or-are-refused)
- [Updating to a new version](#updating-to-a-new-version)
- [Uninstall leftovers](#uninstall-leftovers)
- [Dry-run mode (safe testing)](#dry-run-mode-safe-testing)
- [High CPU, or repeated lines in the log](#high-cpu-or-repeated-lines-in-the-log)
- [Collecting diagnostics](#collecting-diagnostics)

---

## First steps: status, selftest, logs

Menu option **1 Status** shows the same as `status`, plus the program and data folders and the
Tailscale state. From PowerShell:

```powershell
& $exe status          # service state, Telegram state, HTTPS transport, users, monitors, queue, memory
& $exe selftest        # read-only: configuration, permissions, event-log access, Telegram reachability
& $exe users list      # the paired Telegram accounts (id, role, date added, name)
Get-Content "$data\logs\predator.log" -Tail 60
Get-Content "$data\logs\security.log" -Tail 30    # unauthorized messages, pairing attempts, IPC denials, user and feature changes
```

`selftest --tailscale` also queries Tailscale.

The logs rotate at 1 MiB. `predator.log` keeps one previous file (`predator.log.1`), `security.log`
keeps three (`security.log.1` to `security.log.3`). Bot tokens are always redacted, and pairing
codes are never written to any log.

Messages or button presses from Telegram accounts that are not paired, and denied pipe requests
from other Windows accounts, are rate-limited in `security.log`: at most 20 lines per source per
hour and 30 lines per minute overall. Lines beyond that are counted and reported in one summary
line.

`predator.log` is flood-protected as well. A line repeated many times in a row appears once,
followed by `… previous message repeated N times`, and a single place in the code that logs more
than 200 lines a minute is cut off with
`rate limit: N more line(s) from <file:line> were not logged in the previous minute`. See
[High CPU, or repeated lines in the log](#high-cpu-or-repeated-lines-in-the-log).

## Download and setup

### "Windows protected your PC" (SmartScreen)

`PredatorRemoteController.exe` is not code-signed, so Microsoft Defender SmartScreen may block the
first start of a freshly downloaded copy with **Windows protected your PC**.

1. Verify the download first. Download `SHA256SUMS.txt` from the same release and compare:

   ```powershell
   cd $env:USERPROFILE\Downloads
   (Get-FileHash .\PredatorRemoteController.exe -Algorithm SHA256).Hash
   Get-Content .\SHA256SUMS.txt          # lines look like "<sha-256> *PredatorRemoteController.exe"
   ```

   Or as a single check (prints `True` when they match):

   ```powershell
   $expected = ((Select-String -Path .\SHA256SUMS.txt -Pattern 'PredatorRemoteController\.exe').Line -split '\s+')[0]
   (Get-FileHash .\PredatorRemoteController.exe -Algorithm SHA256).Hash -eq $expected
   ```

   If the hashes differ, delete the file and download it again. Never run a copy that does not
   match.
2. In the SmartScreen dialog click **More info**, then **Run anyway**. Alternatively open the
   file's *Properties* and tick **Unblock** before starting it.

The setup itself verifies the tray program embedded in the exe (SHA-256) before it writes
anything, and verifies both installed files after copying them.

### Antivirus quarantined or blocked the program

Remote-control tools are sometimes flagged by heuristics. Symptoms: the download disappears,
setup stops with *Cannot read …* or *Cannot write …*, the service fails to start (System log
event 7000, *The system cannot find the file specified*), the tray icon is gone, or the Network
screen says *the Wi-Fi helper could not be started*.

1. Check the downloaded file against `SHA256SUMS.txt` (see above).
2. Restore it from the antivirus quarantine, or download it again.
3. Add an exclusion for `C:\Program Files\Predator` (and, for the setup, for the downloaded file).
4. If an installed file was removed, repair the installation: run `PredatorRemoteController.exe`,
   choose **7 Uninstall** and answer **No** when asked whether to delete the data folder; then run
   it again. The wizard finds the stored token and the paired accounts and offers to keep them.

### The UAC prompt was declined

Setup always needs administrator rights. When the program is not started elevated it says
*Setup needs administrator rights. Please confirm the Windows prompt (User Account Control); setup
then continues in a new window.* If you choose **No**, or close the prompt, it ends with:

```
Administrator rights were not granted, so nothing was changed.
Run the program again and choose Yes in the Windows prompt.
```

Nothing was installed or changed. Start the program again and choose **Yes**.

- On a standard (non-administrator) account Windows asks for an administrator's user name and
  password. Setup still makes the account that started it the **tray owner**, so the tray icon
  works for that account.
- `setup` with `--data-dir` is refused: the service always uses `%ProgramData%\Predator`.

### Setup messages

| Message | Meaning | What to do |
|---|---|---|
| *That does not look like a bot token (expected 123456789:AAH... as sent by @BotFather).* | The pasted text is not a token. Spaces and line breaks are removed automatically | Copy the token again from @BotFather (`/mybots` → your bot → *API Token*) |
| *Telegram rejected this token (401 Unauthorized).* | The token is wrong, was revoked with `/revoke`, or the bot was deleted | Paste the current token. See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#rotating-the-token) |
| *Could not reach Telegram to verify the token (…)* | No internet, or Telegram is blocked or needs a proxy | Fix the connection and try again; see [Behind a proxy](#proxy) |
| *No working bot token after 5 attempts.* | Five tokens were refused | Run the program again |
| *WARNING: C:\ProgramData\Predator cannot be trusted (…). It was moved to C:\ProgramData\Predator.untrusted-YYYYMMDD-HHMMSS and NOTHING from it is used …* | An existing data folder was not created by Predator: wrong owner, inherited or extra permissions, a junction, or files owned by another account | Nothing in it was used (token, users, settings, queue, audit-policy backup). Setup continues with a new protected folder. Delete the moved folder when you no longer need it |
| *Pairing did not complete: …* followed by *Try again?* | No valid code arrived before it expired, or the code was invalidated | Answer **Yes** and send the new code, or continue without a paired account and pair later from the menu (**2**). See [Pairing code does not work](#pairing-code-does-not-work) |
| *C:\Program Files\Predator already exists and contains files that are not part of Predator (…)* | Setup never takes over a folder of another program | Move those files elsewhere, or delete the folder, and run setup again |
| *… is a junction or symbolic link. Delete it and run setup again.* | The program folder is a link | Delete the link and run setup again |
| *the tray program embedded in this file is damaged (SHA-256 …)* | The download is damaged or was modified | Download the release again and check `SHA256SUMS.txt` |
| *This build does not contain the tray program and … was not found.* | A development build (`predator-service.exe` from `target\release`) was started alone | Use the release file `PredatorRemoteController.exe`, or build it with `scripts\build.ps1` |
| *WARNING: removed … (Predator ships no such files).* | A DLL, `.manifest` or `.local` file was found in the program folder and deleted | Check how it got there. Predator ships no DLLs |
| *The service is marked for deletion. Close services.msc / Event Viewer and try again.* | A previous uninstall is not finished | Close those windows (or reboot) and run setup again |
| *The service did not start: …* and *installed, NOT running* in the summary | Installed, but the start failed | See [Service does not start](#service-does-not-start) |
| *Tray icon: starts at the next sign-in (…)* | The tray could not be started in this session | It starts automatically at the next sign-in; see [Tray icon is hidden or missing](#tray-icon-is-hidden-or-missing) |
| *Nothing was rolled back: fix the problem and run this program again to continue.* | A step failed | Fix the cause shown above it and start the program again; it continues where it stopped |
| *--yes needs --token-file FILE* / *--yes needs --telegram-id ID* | An unattended first install needs both | Add the missing option (see [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#unattended-setup)) |
| *Note: --token-file and --telegram-id are applied only with --yes; use the menu below.* | The program is installed already | Use the menu, or add `--yes` |

`predator-service.exe install` (an advanced command; normally setup does it) refuses to register
the service when its folder or executables can be modified by non-administrators, or when DLL,
OCX, CPL, `.local` or `.manifest` files sit next to the exe: *A LocalSystem service must not run
from a location other accounts can change.* Use setup, which copies and protects the files in
`C:\Program Files\Predator`.

## Service does not start

1. **Check the Windows event logs.**
   - *Event Viewer → Windows Logs → Application*, source **PredatorRemoteController**, event 1000.
     The service writes the reason there when it cannot start, when it crashes, and when it cannot
     register with the Service Control Manager, including failures that happen before its own log
     file is open. The source has no message file, so Event Viewer first shows a "description ...
     cannot be found" preamble; the message text follows it.
   - *Event Viewer → Windows Logs → System*, filtered by source **Service Control Manager**. Look
     for events 7000 (failed to start), 7009 (timeout), 7023 / 7024 (terminated with an error) and
     7031 / 7034 (terminated unexpectedly). The service-specific exit code in event 7024 (also shown
     by `sc.exe query PredatorRemoteController`) means: 1 = start failed, 2 = crashed, 3 = could not
     register its control handler.

   Or in PowerShell:

   ```powershell
   Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'PredatorRemoteController'; StartTime = (Get-Date).AddDays(-1) } |
       Format-List TimeCreated, Id, Message
   Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = (Get-Date).AddDays(-1) } |
       Where-Object Message -match 'Predator' | Format-List TimeCreated, Id, Message
   ```

2. **Read the service log**, `%ProgramData%\Predator\logs\predator.log`. Startup errors are written
   there with a reason.

3. **Check the registration.** The service must be *Automatic*, run as *LocalSystem*, and point at
   an existing exe:

   ```powershell
   Get-CimInstance Win32_Service -Filter "Name='PredatorRemoteController'" | Format-List State, StartMode, StartName, PathName
   Test-Path "C:\Program Files\Predator\predator-service.exe"
   ```

   If the exe is missing (for example removed by antivirus), repair the installation as described
   in [Antivirus quarantined or blocked the program](#antivirus-quarantined-or-blocked-the-program).

4. **Run it in the foreground** to see errors directly. Stop the service first (`console` refuses
   to run while the service runs):

   ```powershell
   & $exe stop
   & $exe console --verbose      # Ctrl+C to stop; console mode always simulates power, lock, logout and Tailscale up/down
   & $exe start
   ```

5. **Common causes:**
   - A command reports that `C:\ProgramData\Predator` *was not created by the Predator installer
     and cannot be trusted*. Stop the service and re-register it from the installed copy; that
     moves the untrusted folder aside and creates a new protected one:

     ```powershell
     & $exe stop
     & $exe install --start
     ```

     Then store the token again (menu **4 Change bot token**) and pair your account (menu
     **2 Pair a Telegram user**). Do not re-create the folder by hand.
   - Antivirus quarantined the exe; see
     [Antivirus quarantined or blocked the program](#antivirus-quarantined-or-blocked-the-program).
   - A crash loop: the SCM restarts the service after 5 s, 10 s and 30 s, and keeps retrying every
     30 s; the failure counter resets after a day. Every failed start adds an Application-log
     entry. Fix the cause, then run `& $exe start`.

A missing or invalid token does **not** stop the service. The monitors keep running and queue
alerts until Telegram becomes reachable.

## Bot token revoked, changed or invalid (401 Unauthorized)

Symptoms:
- `status` shows Telegram `invalid token` (or `not configured` when no token is stored);
- the tray tooltip says `Telegram: invalid token`;
- `predator.log` mentions `401`.

Causes: the token was revoked with `/revoke` in @BotFather, mistyped, or the bot was deleted.

The fix: get the current token from @BotFather (`/mybots` → your bot → *API Token*), then run
`PredatorRemoteController.exe` and choose **4 Change bot token**. The token is typed into a hidden
prompt and checked with Telegram before it is stored. Answer **Yes** to *Restart the service now so
it uses the new token?*

The same from PowerShell:

```powershell
& $exe set-token        # hidden prompt; paste the current token
& $exe stop
& $exe start
```

- Paired accounts stay authorized: they are stored by numeric Telegram user id, not per token.
- With the token of a **different** bot, every paired person must open the new bot and press
  **Start** once, otherwise Telegram cannot deliver its messages.
- With a 401, the service re-checks the stored token only every 30 minutes, so restart it to apply
  the new token immediately.

See [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#rotating-the-token) for rotating a leaked token.

## The bot does not answer

- **Is any account paired?** `status` shows `Telegram users: paired` or `none yet`;
  `& $exe users list` lists them. Without a paired account every message except a pairing code is
  rejected. Pair one with menu **2** (see [TELEGRAM_SETUP.md](TELEGRAM_SETUP.md#5-pair-your-telegram-account)).
- **Is your account paired?** An account that is not in the list gets
  `⛔ Access denied. This bot is private.` (at most once an hour) and every paired user gets an
  **🚨 UNAUTHORIZED ACCESS ATTEMPT** alert. The attempt is logged in `security.log` with the
  sender's numeric id, so you can compare it with `users list`.
- **Are you writing in a private chat?** The bot leaves every group and channel it is added to.
  Only your own private chat with the bot is accepted.
- **Is it the right bot?** Each PC has its own bot. `status` and the menu header show its
  `@username`; menu **6 Open the bot in Telegram** opens the right chat.
- **Is the PC online?** While Windows reports no internet, the service waits for a network change,
  but at most 60 seconds, and then tries Telegram anyway. Commands are answered when it reconnects,
  but state-changing commands older than 5 minutes and late state-changing button presses are
  skipped (see [Queue and offline behaviour](#queue-and-offline-behaviour)).
- **Is the token valid?** See [Bot token revoked, changed or invalid](#bot-token-revoked-changed-or-invalid-401-unauthorized).
- **Does this network need a proxy, or block direct HTTPS?** `status` shows Telegram `offline`
  while browsing works, and `predator.log` shows `Telegram getMe failed: …` or
  `Telegram getUpdates failed: …` with `cannot connect to the server`, `cannot resolve the server
  name`, `TLS handshake failed` or `server certificate rejected`. The line is written at the first
  failed attempt and then at every 20th. See
  [Behind a proxy / Telegram unreachable — force WinHTTP](#proxy).
- Edited messages are never executed; send the command again instead of editing it.
- See also [409 Conflict](#409-conflict).

## Pairing code does not work

A new Telegram account is added only with a one-time code created **on the PC**: tray menu
**Pair Telegram User…**, setup menu **2 Pair a Telegram user**, or `& $exe pair [--admin] [--ttl SECS]`.
The person sends `/pair 1234 5678` to the bot in a private chat, or opens the link
`https://t.me/<bot>?start=pair-12345678` shown on the PC and presses **Start**.

To protect the PC, the bot never tells a sender *why* a code failed. A wrong, expired, used or
invalidated code is answered exactly like any message from a stranger
(`⛔ Access denied. This bot is private.`, at most once an hour per account; during the first
setup, while the setup window itself waits for the code, failed attempts get no reply at all).
So **check on the PC**:

- The console (menu or `pair`) shows `Paired: … (Telegram user id …)`, or why the code ended:
  *The pairing code expired without being used*, *Too many wrong pairing codes: the code was
  invalidated*, *A new pairing code was created elsewhere (tray or another console)*, or *The
  service stopped, so the pairing code is no longer valid*.
- The tray shows a notification: *Telegram account paired*, *Pairing code expired*, or *Pairing
  code no longer valid*.
- `security.log` records every attempt with the reason (never the code), for example
  `… — pairing failed: wrong code`:

  ```powershell
  Select-String -Path "$data\logs\security.log" -Pattern 'pairing|paired' | Select-Object -Last 20
  ```

| Cause | What to do |
|---|---|
| **Expired.** Codes are valid for 10 minutes by default (tray and menu); `pair --ttl SECS` allows 60 … 3600 s | Create a new code |
| **Used.** A code works once | Create a new code for the next account |
| **Invalidated.** After 5 wrong attempts in total (from anyone) the code is dead, even for the right digits | Create a new code |
| **Replaced.** Only one code is active at a time; a new one from the tray, the menu or another console replaces it | Use the newest code |
| **Cancelled.** Ctrl+C in the console, closing the window, or a service restart (codes live in memory only) ends it | Create a new code |
| **Rate limit for that account.** One Telegram account may make 5 wrong guesses per hour (across all codes); after that even the right code is refused for the rest of the hour | Wait an hour, or pair from another account |
| **Already paired.** The account is in the list already | The bot answers `ℹ️ You are already paired.` and the code stays valid |
| **User limit.** 20 accounts are paired | The PC refuses to create a code (*20 Telegram accounts are paired already (the maximum). Remove one first …*). Remove an account with `/users` or menu **3** |
| **Wrong chat.** Sent in a group, from another account than the one to add, or to a different bot | Open the private chat with this PC's bot (the link on the PC opens the right one) from the account to add |
| **Typo.** Spaces and dashes are fine (`1234 5678`, `1234-5678`); other characters are not. A bare `/pair` without a code costs no attempt | Send `/pair` followed by the 8 digits |
| **The service cannot reach Telegram.** `pair` says *The service cannot reach the bot (…)* or *Note: the service is not connected to Telegram right now* | Fix the token or the connection first |

The first account of an empty list always becomes an **Admin**. Later accounts get the role
**User**, unless the code was created for an Admin (`pair --admin`, or **Yes** to *Make this
account an Admin* in the menu).

## `pair` or `users remove` is refused on the PC

| Message | Why | What to do |
|---|---|---|
| *The Predator service is starting. Wait a few seconds until it runs, then try again.* | A starting service has already read its settings and polls the bot; neither the CLI nor the service could handle the pairing or removal safely | Wait until `status` shows `Running`, then try again |
| *The Predator service is stopping. Wait until it has stopped (or start it again), then try again.* | The same while it stops | Wait, then try again |
| *The state of the Predator service is unclear …* | The service is paused or the SCM could not be asked | `& $exe start` or `& $exe stop`, then try again |
| *Only an elevated administrator can create a pairing code for an Admin account.* | Admin codes need an elevated prompt while the service runs (an Admin can remove other accounts) | Use an elevated PowerShell, or the setup menu, or pair the account as a User |
| *Removing a Telegram account needs an elevated (Administrator) prompt on this PC, or an Admin account in Telegram (/users).* | Removing accounts from the PC needs elevation | Use an elevated PowerShell or the setup menu (**3**), or remove it in Telegram with `/users` |
| *The last admin cannot be removed (pair another admin first).* | Someone must be able to manage the list | Pair a second Admin first |
| *Telegram user N is not authorized.* | No such id in the list | Check the id with `& $exe users list` |
| *The running service did not answer …, so the account was NOT removed.* | The service runs but its local pipe did not respond; editing the settings behind its back would leave the account authorized | Restart the service (`& $exe stop`, then `& $exe start`) and try again |
| *This Windows account is not allowed to control Predator …* | Neither the tray owner nor an elevated administrator | Use an elevated prompt |
| *No bot token stored yet. Run 'predator-service set-token' first.* | The service is stopped and no token is stored | Store the token (menu **4**) |

While the service runs, `pair` (User role) works from the tray owner's normal prompt; the service
creates and redeems the code. While the service is stopped, `pair` polls Telegram itself and needs
an elevated prompt.

In Telegram, `/users` lists every account (`👑` Admin, `👤` User). Admins get a
`🗑 Remove <name>` button for every other account; removal is immediate and every remaining user
is told (*TELEGRAM USER REMOVED*). Admins cannot remove their own account in Telegram: another
admin, or an administrator on the PC (menu **3** or `users remove ID`), must do it.

`set-owner --telegram-id ID` replaces **all** authorized accounts by that one account (Admin), for
example after an account was compromised.

## A second user gets no alerts

Every alert goes to every paired account. When one account does not receive them:

1. **Is it paired?** `& $exe users list` or `/users`. A removed account receives nothing more.
2. **Did that person block the bot, or never press Start?** Telegram then refuses delivery
   (`403 Forbidden`, or *chat not found*). That account is skipped so it never holds back the
   others, and `predator.log` says once:
   `notification #N not delivered to Telegram user 123456789 (…): that account blocked the bot or
   never pressed Start; skipped (the other users have it)`. Ask the person to open the bot chat
   and unblock it (or press **Start**). Alerts skipped meanwhile are not sent again.
   An account added with `--telegram-id` or `set-owner` has never talked to the bot: it must open
   the bot and press **Start** once.
3. **Did the bot change?** After a token of a different bot, every person must open the new bot
   and press **Start**.
4. **Is the alert type switched on?** `/features` is shared by everyone: *Login Notifications*,
   *Logout Notifications*, *Failed Login Notifications* (off by default) and *SSH Monitoring*.

When **nobody** can be reached, notifications stay queued and are retried every 30 minutes;
`predator.log` then says `Telegram refuses to deliver to every paired user (…)`. Accounts paired
later also receive what is still queued.

## 409 Conflict

`409 Conflict: terminated by other getUpdates request` means another program is polling the same
bot token. Common culprits:

- a second Predator installation, on another PC or in a VM, using the same token (every PC needs
  its own bot);
- `predator-service.exe console` with `--data-dir` and `--token-file` for the same bot while the
  service is running;
- another script or bot framework that you tested with this token;
- a **webhook** set by another tool. The service removes webhooks once per token, but another
  program can set one again.

Stop the other program. If you cannot find it, revoke the token in @BotFather (`/revoke`) and store
the new one with menu **4 Change bot token**; every other copy then stops working. The service
retries with backoff and recovers by itself once the conflict is gone.

<a id="proxy"></a>

## Behind a proxy / Telegram unreachable — force WinHTTP

Normally the service talks to Telegram over its own direct HTTPS connection (a TCP socket to
`api.telegram.org` port 443, TLS by Windows' SChannel). That needs no proxy and does not load
WinHTTP, which saves memory and wake-ups. WinHTTP, Windows' HTTP stack with proxy support, is only
the fallback. The service picks it:

1. **At start**, when a proxy is configured where the service can see it:
   - a machine-wide WinHTTP proxy (`netsh winhttp show proxy` shows it) → *WinHTTP (default
     proxy)*;
   - a manual proxy or a proxy script (PAC) in the Internet Settings that apply to the service →
     *WinHTTP (automatic proxy)*. The service runs as LocalSystem, so these are LocalSystem's own
     settings, or the machine-wide ones when the Group Policy setting *Make proxy settings
     per-machine (rather than per-user)* is on. **A proxy you set for your own account (Settings →
     Network & internet → Proxy) is not seen by the service.** *Automatically detect settings*
     alone does not count either.
2. **At run time**, when direct connections keep failing (3 failed connection attempts spread over
   at least 60 seconds, while Windows does not report "no network" at all): the service sends one
   test request through WinHTTP with automatic proxy detection (WPAD, PAC, Internet Settings). Only
   if that request reaches Telegram does it switch to WinHTTP, until the service restarts, and logs
   a warning. If the test fails too (an ordinary outage), it stays on the direct connection and
   tests again after 6, 12, 24 and then every 48 further failures.

The transport is chosen when the service starts (or loads a new token), so restart it after
changing any proxy setting.

**Make the proxy visible to the service (recommended).** If your own account uses a manual proxy,
copy it to the machine-wide WinHTTP setting and restart the service. In an elevated PowerShell
started from that account:

```powershell
netsh winhttp import proxy source=ie     # copies your account's manual proxy (not a PAC script)
netsh winhttp show proxy
& $exe stop; & $exe start
& $exe status                           # HTTPS transport: WinHTTP (default proxy)
```

Or set it explicitly: `netsh winhttp set proxy proxy-server="proxy.example:8080"
bypass-list="<local>"`. `netsh winhttp reset proxy` removes it again (then restart the service).

**Force WinHTTP.** When the direct connection does not work on this network and the automatic
switch does not happen, force the transport with the environment variable
`PREDATOR_HTTP_TRANSPORT`. One case the automatic switch cannot catch: a network device that lets
the TLS handshake through and breaks the connection only afterwards. Such failures count as
"server reached", so they never trigger the test request.

For the service the variable goes into the service's own `Environment` registry value
(`REG_MULTI_SZ`) under `HKLM\SYSTEM\CurrentControlSet\Services\PredatorRemoteController`. Elevated
PowerShell:

```powershell
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PredatorRemoteController'
# Keep other entries the value may already have; replace an older PREDATOR_HTTP_TRANSPORT line.
$old = (Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment
$new = @($old | Where-Object { $_ -and $_ -notlike 'PREDATOR_HTTP_TRANSPORT=*' }) + 'PREDATOR_HTTP_TRANSPORT=winhttp'
New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString -Value $new -Force | Out-Null
& $exe stop; & $exe start                # the service reads its environment only when it starts
& $exe status                            # HTTPS transport: WinHTTP (default proxy) or (automatic proxy)
```

The same with `reg.exe`, when the service has no other `Environment` entries:
`reg add "HKLM\SYSTEM\CurrentControlSet\Services\PredatorRemoteController" /v Environment /t REG_MULTI_SZ /d "PREDATOR_HTTP_TRANSPORT=winhttp" /f`.

| Value | Effect |
|---|---|
| `winhttp` | Always WinHTTP, never the direct connection. *Default proxy* mode when a machine-wide WinHTTP proxy is set or no proxy is configured anywhere; *automatic proxy* mode when only the Internet Settings name a proxy or PAC script. From *default proxy* it can still move to *automatic proxy* if that is shown to reach Telegram |
| `direct` | Always the direct connection, with no automatic fallback. For diagnostics: it shows whether the direct path itself works |
| `auto` or not set | The normal behaviour described above |

Values are not case-sensitive. Anything else is ignored, and `predator.log` says
`PREDATOR_HTTP_TRANSPORT="…" is not recognised (use direct or winhttp); ignored`.

To undo it (elevated):

```powershell
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\PredatorRemoteController'
$keep = @((Get-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue).Environment |
    Where-Object { $_ -and $_ -notlike 'PREDATOR_HTTP_TRANSPORT=*' })
if ($keep.Count) { New-ItemProperty -Path $svcKey -Name Environment -PropertyType MultiString -Value $keep -Force | Out-Null }
else { Remove-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue }
& $exe stop; & $exe start
```

Good to know:
- Setting the variable in a PowerShell window (`$env:PREDATOR_HTTP_TRANSPORT = 'winhttp'`) affects
  only the commands you start from that window (`selftest`, `set-token`, and a `pair` that runs
  while the service is stopped), never the running service.
- An update from the menu keeps the `Environment` value. Uninstalling deletes the service and the
  value with it.
- If even WinHTTP cannot reach Telegram, the cause is not the transport: check DNS
  (`Resolve-DnsName api.telegram.org`), the firewall, and whether Telegram is blocked on this
  network. `Test-NetConnection api.telegram.org -Port 443` tests the direct path from your account.
- `server certificate rejected` means Windows did not trust the certificate it was shown, for
  example behind a TLS-inspecting proxy whose root certificate is not installed in the machine's
  trust store. Predator never skips certificate validation; install the organisation's root
  certificate in *Local Computer → Trusted Root Certification Authorities* or exempt
  `api.telegram.org` from inspection.

## How to see which HTTPS transport is used

```powershell
& $exe status                     # "HTTPS transport: ..." of the running service
Select-String -Path "$data\logs\predator.log" -Pattern 'HTTP transport|HTTPS transport|HTTPS:|PREDATOR_HTTP_TRANSPORT' |
    Select-Object -Last 10
```

| Shown as | Meaning |
|---|---|
| `direct (SChannel)` | The normal path: own TCP connection with SChannel TLS. `winhttp.dll` is not needed |
| `WinHTTP (default proxy)` | WinHTTP with the machine-wide WinHTTP proxy setting (or none). Chosen because `netsh winhttp` has a proxy, or forced with `PREDATOR_HTTP_TRANSPORT=winhttp` |
| `WinHTTP (automatic proxy)` | WinHTTP with automatic proxy detection (WPAD, PAC, Internet Settings). Chosen because the Internet Settings name a proxy or PAC script, or the service switched to it after direct connections (or WinHTTP with the default proxy) kept failing |

- `status` prints the line only when the service runs with a bot token loaded.
- `predator.log` lines:
  - `Telegram bot token loaded (HTTP transport: …)`: the transport chosen at start or after a new
    token;
  - `HTTPS transport: WinHTTP (…) (<reason>)`: why WinHTTP was chosen at start (for example
    `a WinHTTP proxy is configured (netsh winhttp)`);
  - `HTTPS: the direct connection to the server kept failing while WinHTTP with automatic proxy
    detection reached it; using WinHTTP (system proxy support) until the service restarts`: the
    run-time switch (from *WinHTTP (default proxy)* the line starts `HTTPS: WinHTTP with the
    default proxy setting kept failing …`);
  - `HTTPS: WinHTTP with automatic proxy detection did not reach the server either; keeping the
    current connection method (next check after N more connection failures)`: a test request
    failed; nothing changed.
- `& $exe selftest` prints `Telegram HTTP transport: …` too, but that is the choice of the
  selftest process itself (your PowerShell's environment and your account's Internet Settings),
  not necessarily the service's. Use `status` for the service.
- To check whether WinHTTP is loaded in the service at all (elevated; without elevation the module
  list shows `N/A`):

  ```powershell
  $svcPid = (Get-CimInstance Win32_Service -Filter "Name='PredatorRemoteController'").ProcessId
  tasklist /m winhttp.dll /fi "PID eq $svcPid"     # "No tasks are running ..." = not loaded
  ```

  `winhttp.dll` can stay loaded after a test request that failed, so `status` is the authoritative
  answer.

## No Windows login alerts

1. **Feature switches.** In `/features`, *Windows Login Monitoring* and *Login Notifications* must
   be 🟢. *Failed Login Notifications* is **off by default**. Turn it on if you want failed-login
   alerts. `& $exe features list` shows the same.

2. **Audit policy.** Windows writes logon events to the Security log only when the matching audit
   subcategories are enabled. Setup enables them (and saves the original values, which uninstall
   restores). Group Policy, Intune/MDM or a security baseline can switch them off again. The
   service re-checks the policy every 10 minutes and at once when Windows logs an audit-policy
   change (event 4719). When the policy is no longer sufficient it sends an **AUDIT POLICY
   INSUFFICIENT** alert, and while logon auditing is off it reports sign-ins from Windows session
   notifications instead (with less detail).

   ```powershell
   & $exe audit status                         # Predator's view, with a sufficient / insufficient verdict
   auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"    # Logon: needs Success and Failure
   auditpol /get /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}"    # Logoff: needs Success
   auditpol /get /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}"    # Other Logon/Logoff: needs Success (unlock, RDP reconnect)
   & $exe audit enable                         # re-enable (saves the original values first, once)
   ```

   The GUIDs work on every Windows display language. If the policy keeps reverting, check
   `gpresult /h gp.html` for an *Advanced Audit Policy Configuration* that overrides it.

3. **Monitor state.** `/status`, or the main menu header, shows `Login monitor: 🟢 Active`. If it
   shows an error, see `predator.log`. The Security log can only be read by LocalSystem or an
   administrator, so the service must run as LocalSystem. After a read error the monitor reopens
   the log at once (at most once every 5 minutes), otherwise it retries with a growing delay
   (5 seconds up to 10 minutes) and shows the error state meanwhile. Sign-ins are then reported
   from Windows session notifications. See
   [High CPU, or repeated lines in the log](#high-cpu-or-repeated-lines-in-the-log) for the log
   lines.

4. **Expected behaviour that is not a fault:**
   - Background logons (services, scheduled tasks, network share access, Window Manager and Font
     Driver accounts) are filtered out on purpose.
   - An administrator's sign-in creates two linked logon events (UAC). Predator reports it once.
   - An RDP reconnect creates a logon event and a reconnect event, and often a console disconnect.
     Predator reports it as one alert.
   - A burst of failed logins is limited to 10 alerts per 10 minutes; the rest are summarized (see
     [Queue and offline behaviour](#queue-and-offline-behaviour)).

5. **Fast Startup.** With Fast Startup on, *Shut down* hibernates the Windows session that runs
   services instead of ending it, so the service is not restarted at the next power-on: it
   continues where it was and keeps monitoring.

## No SSH alerts

1. **Feature switch.** *SSH Monitoring* must be 🟢 in `/features`. Successful SSH logins also need
   *Login Notifications*.

2. **Is the OpenSSH/Operational channel enabled?**

   ```powershell
   Get-WinEvent -ListLog 'OpenSSH/Operational' | Format-List LogName, IsEnabled, RecordCount
   wevtutil sl OpenSSH/Operational /e:true          # enable it if IsEnabled is False
   Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 5 | Format-List TimeCreated, Id, Message
   ```

   If the channel does not exist, the OpenSSH Server feature is not installed. "Maximum
   authentication attempts exceeded" alerts come from the `OpenSSH/Admin` channel, which is
   optional.

3. **sshd_config** (`%ProgramData%\ssh\sshd_config`):
   - `SyslogFacility` must **not** be `LOCAL0`. That value sends the logs to
     `%ProgramData%\ssh\logs\sshd.log` instead of the event log. Remove the line, or use the default
     (`AUTH`).
   - `LogLevel` must be `INFO` (the default) or `VERBOSE`. `QUIET`, `FATAL` and `ERROR` suppress the
     "Accepted ..." lines. Check `Match` blocks as well.
   - sshd reads its configuration only at start. After editing, restart it:

     ```powershell
     Restart-Service sshd
     ```

     New connections use the new settings.

4. **SSH user names** are shown exactly as the client typed them (`alex`, `DESKTOP-01\alex`, ...).
   Some sessions never log an end, so an "SSH session closed" alert may not appear for every
   session.

## Network and battery screens

**`🚫 Network Information is disabled.`** / **`🚫 Battery Information is disabled.`** The feature
is switched off; enable it in `/features`.

**Battery.** A desktop PC shows `🔌 No battery detected — this PC runs on AC power.`; that is
normal. `❌ Could not read the battery status: …` means Windows did not answer the power-status
query; the text names the reason.

**SSID unavailable on the Network screen.**

- **Ethernet** connections have no SSID line; that is normal.
- **On Wi-Fi**, the service starts a short-lived helper, `predator-service.exe ssid-helper`, which
  tries the WLAN API, then the WinRT API `WlanConnectionProfileDetails.GetConnectedSsid()`, then
  the Network List Manager. The WinRT step works with Windows **Location services turned off**. If
  the line is replaced by an italic note:
  - Check that the *WLAN AutoConfig* service (`wlansvc`) is running: `Get-Service wlansvc`.
  - Check that you are actually connected: `/network` shows `Connection: Wi-Fi`.
  - *the Wi-Fi helper could not be started* or *the Wi-Fi helper failed* means the child process
    did not run or gave no answer. Check that `predator-service.exe` is intact in the program
    folder, and that antivirus does not block it from starting itself. *Windows did not answer in
    time* means the helper was stopped after 8 seconds; try again.
  - *Windows location services are off* or *the WLAN AutoConfig service is not running* name the
    cause directly.
  - On some managed PCs, policy blocks the classic WLAN API. Turning on **Settings → Privacy &
    security → Location → Location services** for the device also unlocks that API. This is
    optional, and Predator never changes the setting itself.
- Predator never collects BSSIDs or scan results, so no location permission is required.

## Remote Desktop and SSH over Tailscale

Telegram cannot give you the PC's desktop or a shell. **Tailscale** gives the PC a private,
encrypted address that you can reach from anywhere (a phone on mobile data, a laptop on another
network) without port forwarding and without exposing RDP or SSH to the internet. Predator can
switch Tailscale on and off from Telegram, so it only runs while you need it.

**One-time preparation on the PC:**

1. Install Tailscale for Windows from tailscale.com and sign in once.
2. In the Tailscale app choose **Preferences → Run unattended**. Then Tailscale (and Tailscale Up
   from Telegram) also works when nobody is signed in to Windows, for example after a reboot or a
   power cut.
3. Enable what you want to use remotely:
   - **Remote Desktop**: *Settings → System → Remote Desktop* (Windows Pro, Enterprise or
     Education; Windows Home cannot accept Remote Desktop connections).
   - **SSH**: the *OpenSSH Server* optional feature and its `sshd` service.
4. Make sure the *Tailscale Management* feature is 🟢 in `/features`.

**When you need the PC:**

1. Send `/tailscale up`, or open **🛡 Tailscale** in `/menu` and press **▶️ Up**. Predator starts
   the `Tailscale` service, starts the Tailscale app (`tailscale-ipn.exe`) in the signed-in user's
   session when it is not running, waits up to 30 seconds for the connection and runs a plain
   `tailscale up` only if it is still not connected. The result shows every step and the current
   status, including `Tailscale IP` and `Hostname`.
2. Connect from your other device (which must be in the same tailnet):

   ```powershell
   mstsc /v:100.64.0.5          # Remote Desktop to the Tailscale IP (or the MagicDNS name, e.g. desktop-01)
   ssh alex@100.64.0.5          # SSH
   ```

3. When you are done, send `/tailscale down` or press **⏹ Down**. Predator closes the Tailscale
   app in every session and stops the `Tailscale` service, so nothing is listening on the tailnet
   and nothing uses resources.

If the connection times out although Tailscale shows `🟢 Connected`, check that Remote Desktop or
`sshd` is enabled and that Windows Firewall allows it for the network profile of the Tailscale
adapter. `/tailscale up` and `/tailscale down` older than 5 minutes (for example sent while the PC
was offline) are not executed.

## Tailscale errors

| Message / state | Meaning | What to do |
|---|---|---|
| *Tailscale is not installed* | `tailscale.exe` was not found through the registry (`HKLM\SOFTWARE\Tailscale IPN`), the `Tailscale` service, or `%ProgramFiles%\Tailscale` | Install Tailscale for Windows from tailscale.com, or repair the installation |
| `🔴 Disconnected (Tailscale service stopped)` | The `Tailscale` Windows service is not running (also the normal result of `/tailscale down`, together with `App: ⚪ Not running`) | `/tailscale up` starts the service and the Tailscale app, then runs a plain `tailscale up` if it is still not connected |
| `🟡 Connecting…` with `App: ⚪ Not running` | The backend is in `NoState`: on Windows it waits for the Tailscale app of a signed-in user | Send `/tailscale up`, which starts the app. See [Tailscale app not running / stuck in NoState](#tailscale-app-not-running--stuck-in-nostate) |
| `🟡 Needs login` | Tailscale itself is logged out: no Tailscale account is signed in for the profile in use. (A Windows user who is merely signed out shows `🟡 Connecting…` with `App: ⚪ Not running` instead, see the row above) | Sign in to Tailscale on the PC. To keep it connected without anyone signed in, enable **Run unattended** (Tailscale menu → Preferences), or run `tailscale set --unattended=true` **as the profile owner** |
| `🟡 Needs admin approval` | The tailnet requires device approval | Approve the PC in the Tailscale admin console |
| Login URL shown | Tailscale wants an interactive login | Open it only yourself: whoever completes it attaches the PC to *their* tailnet |
| *... was refused for the service account ... retrying as &lt;user&gt;* | The profile belongs to a Windows user, and SYSTEM may not run the command | Predator ran the same plain command inside that user's session. If nobody is signed in, `/tailscale down` still stops the `Tailscale` service, which disconnects every user on this PC |
| `🟡 In use by another Windows user` | Another Windows user is currently using the Tailscale app | Use the account that owns the Tailscale profile, or switch the profile |
| `🟡 Connecting…` / `🟡 Starting…` with `App: 🟢 Running` | tailscaled is still contacting the control server (often right after boot or while offline) | Wait and press 🔄 Refresh |
| `⏳ A Tailscale operation is already running.` | Only one up/down runs at a time. Up or down can take up to 1–2 minutes when a step reaches its time limit | Wait for the first one to finish |
| *Tailscale is still starting after 30 s (state: NoState) — the Tailscale app is not running* | The app could not be started, or exited | See [Tailscale app not running / stuck in NoState](#tailscale-app-not-running--stuck-in-nostate) |
| *… — nobody is logged in to Windows, so only Run unattended can connect it* / *No user is logged in — relying on Tailscale Unattended mode* | Nobody is signed in, so there is no session to start the app in | Sign in to Windows, or enable **Run unattended** in Tailscale |
| *Could not start the Tailscale app for &lt;user&gt;: …* | Windows refused to start `tailscale-ipn.exe` in that user's session | See the reason in the message and in `predator.log`; start Tailscale from the Start menu once to check it works |
| *The Tailscale app (tailscale-ipn.exe) was not found next to tailscale.exe — not started* | The installation is incomplete | Repair or reinstall Tailscale |
| *The Tailscale app exited right after it was started* | The app started but closed again at once | Start Tailscale from the Start menu and look for an error; repair the installation if needed |
| *Left tailscale-ipn.exe alone — not the installed Tailscale app (…)* | `/tailscale down` found a `tailscale-ipn.exe` outside the Tailscale install folder and did not touch it | Check where that program comes from (the path is shown) |
| *The Tailscale app is still running (PID …)* / *Could not close the Tailscale app* | `/tailscale down` could not terminate the app | Close it from its tray icon (*Exit*), then send `/tailscale down` again |
| *disconnect not allowed: always-on mode is enabled* | A Tailscale administrator policy (always-on) forbids disconnecting | Expected; change the policy if needed |
| `🚫 Tailscale Management is disabled.` | The feature switch is off | Enable it in `/features` |

Health warnings reported by tailscaled are shown on the status screen (at most 3). Status is read
with `tailscale status --json --peers=false`; an old CLI that does not know `--peers` is detected
and queried with plain `status --json` instead.

## Tailscale app not running / stuck in NoState

On Windows the Tailscale backend stays in `NoState` until the **Tailscale app**
(`tailscale-ipn.exe`, the Tailscale tray icon) of a signed-in user connects to it, unless
**Run unattended** is on. The status screen then shows `Connection: 🟡 Connecting…` and
`App: ⚪ Not running`. You see this whenever the service runs but the app does not, for example
after the service was started by hand or someone exited the Tailscale app.

What `/tailscale up` does about it:
1. starts the `Tailscale` service if needed;
2. starts the app in the active user's session (console first, otherwise an active Remote Desktop
   session) when it is not running in any session;
3. waits up to 30 seconds for the backend to leave `NoState`;
4. runs a plain `tailscale up` only if Tailscale is still not connected, and checks the result.

If it does not connect:

- **Nobody is signed in to Windows.** The app can only run in a user session. Sign in, or enable
  **Run unattended** (Tailscale menu → Preferences, or `tailscale set --unattended=true` run by
  the profile owner) so Tailscale connects without the app.
- **The app does not start.** The result lists *Could not start the Tailscale app …* or *The
  Tailscale app exited right after it was started*. Start Tailscale once from the Start menu as
  that user to see its own error, and repair the installation if needed. `predator.log` has
  matching `tailscale:` / `session:` lines.
- **The app runs, but the state stays `NoState` or `Needs login`.** The Tailscale profile may
  belong to another Windows user, or the user is logged out of Tailscale. Open the Tailscale tray
  icon as the profile owner and sign in.
- **Check by hand** (normal PowerShell):

  ```powershell
  Get-Process tailscale-ipn -IncludeUserName -ErrorAction SilentlyContinue | Format-Table Id, SessionId, UserName, Path
  & "$env:ProgramFiles\Tailscale\tailscale.exe" status --json --peers=false | Select-String BackendState
  ```

  `-IncludeUserName` needs an elevated PowerShell; drop it otherwise.

`/tailscale down` closes the app on purpose (every `tailscale-ipn.exe` in the Tailscale install
folder, in every session) and stops the service, so the PC is fully off Tailscale. A
`tailscale-ipn.exe` elsewhere is never touched; the result names it.

## Old bot messages are not deleted

The chat auto-clean deletes menus, replies, status notices and your own commands: when you send
the next command, after `chat_clean_after_secs` without use (default 10 minutes), or at once with
`/clear`. Some messages are kept on purpose or cannot be deleted:

| What you see | Why | What to do |
|---|---|---|
| Login, logout, failed-login, SSH or security alerts stay | They are **always kept**; that is the point of the feature | Nothing. Delete single alerts by hand in Telegram if you want |
| Messages from while auto-clean was switched off stay, and `/clear` does not remove them | Only messages sent while it is on are tracked | Use Telegram's **Clear history** once in the bot chat (chat menu → *Clear history*). Login alerts in that history are deleted too, so scroll through them first |
| Messages older than **48 hours** stay | Telegram does not let bots delete them; Predator drops them from its list after 47 hours | Delete them by hand or with *Clear history* |
| A power confirmation (`⚠️ CONFIRM SHUTDOWN`) stays | It is kept while it can still be confirmed | Once it is confirmed, cancelled or expired it is cleaned like any other reply: with your next message, or after `chat_clean_after_secs` without use. `/clear` removes it at once and cancels it |
| The first `/pair` message and its `✅ Paired with …` reply stay | During the first setup the setup window exchanges them itself (the service is not running yet), so they are not tracked. Later pairings go through the service and are cleaned like any other command | Delete them by hand |
| Nothing is deleted at all; `/clear` says *Automatic chat cleaning is switched off* | `auto_clean_chat` is `false` in `settings.json` | Set it to `true` (elevated editor), then `& $exe stop; & $exe start` |
| Replies stay much longer than 10 minutes | `chat_clean_after_secs` is larger, or Predator was offline (the time-based cleanup runs only while it reaches Telegram) | Check the value in `settings.json` (60 … 169200 seconds). Leftovers go with your next command |
| Messages from before a **bot token change** stay | The list belongs to the previous bot; its entries are forgotten, never deleted (their ids could match the new bot's login alerts) | Delete them by hand in the old bot's chat |
| Nothing is deleted and `predator.log` shows `chat cleanup: cannot delete …` | Telegram refused the deletion (for example, you blocked the bot) | Unblock the bot; new messages are cleaned again |

Check the settings and the list (elevated PowerShell):

```powershell
Get-Content "$data\settings.json" | Select-String 'auto_clean_chat|chat_clean_after_secs'
Get-Content "$data\chat-cleanup.json"            # {version, bot_id, entries:[{chat_id, message_id, sent_unix, active_unix}]}
Select-String -Path "$data\logs\predator.log" -Pattern 'chat cleanup|/clear' | Select-Object -Last 20
```

`chat-cleanup.json` holds only ids and times, never message text. A corrupt file is renamed to
`chat-cleanup.json.corrupt` and the list starts empty; at worst a few messages then have to be
deleted by hand. Deletions that failed because of the network are retried at the next cleanup
round.

## Tray icon is hidden or missing

- **Hidden in the overflow area (^):** open *Settings → Personalization → Taskbar → Other system
  tray icons* and turn on **Predator Remote Controller Tray** (the tray app's file description).
  You can also drag the icon from the overflow onto the taskbar.
- **Not running:**
  - The tray starts at sign-in from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` → value
    `PredatorTray`. Check it with
    `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PredatorTray`.
  - Start it by hand by double-clicking `C:\Program Files\Predator\predator-tray.exe` (not as
    administrator).
- **Starts and exits immediately:** the tray exits silently when the service refuses its
  requests, which means your Windows account is not the configured tray owner. Setup makes the
  account that started it the owner. To change it (elevated):
  `& $exe set-owner-sid --user "DESKTOP-01\alex"`. The running service applies it at once.
- **Grey icon or disabled items:** the service is not running. Use `& $exe start`, or the tray's
  *Start Service (admin)…* item, which asks for elevation. *Restart Service*, *Pair Telegram
  User…* and *Telegram Users…* stay greyed out until the service runs.

## Queue and offline behaviour

- While the PC has no internet, alerts are queued in `%ProgramData%\Predator\queue.json`. They
  survive reboots.
- When connectivity returns, they are sent in order, each with its original time and a note
  `📨 Delivered late — queued while offline (sent HH:MM:SS)`.
- The queue keeps at most 1000 alerts. Older ones are dropped when it overflows, and the number
  dropped is counted.
- Each alert is recorded per recipient, so after an outage or a restart it goes only to the paired
  accounts that do not have it yet.
- **The same alert arrived twice after a crash or power cut?** Expected, and rare. New alerts are
  written to `queue.json` at once, but delivered ones are removed from the file in batches (at most
  every 2 seconds, at once when the queue becomes empty, and when the service stops). An alert
  delivered just before a crash can therefore be sent once more after the restart. No alert is
  ever lost.
- `Queued alerts: N` in the menu shows the backlog.
- A network change or a resume from sleep ends the retry backoff and cuts a waiting long poll
  short at once, so a queue normally drains within seconds of the connection coming back. If it
  takes much longer, the service may be in a long backoff; restart it or wait for the next network
  change. If alerts never arrive although the internet works, see
  [Behind a proxy / Telegram unreachable — force WinHTTP](#proxy).
- If it stays above 0 while the PC is online, check the token (401), whether any account is paired
  (`users list`), whether every account blocked the bot (`403 Forbidden`, see
  [A second user gets no alerts](#a-second-user-gets-no-alerts)), and `predator.log`.
- Commands you sent while the PC was offline are delivered by Telegram when it comes back. Telegram
  keeps them for up to 24 hours. Read-only commands are answered. `/shutdown`, `/restart`,
  `/sleep`, `/hibernate`, `/lock`, `/logout`, `/tailscale up` and `/tailscale down` older than 5
  minutes are **not executed**; you get
  `⌛ Ignored /lock sent at 14:02:11 — older than 5 minutes (sent while the PC was offline?)`.
- Button presses carry no time stamp. Presses that Telegram had queued while Predator was not
  polling (right after the service starts, or after more than 90 seconds without reaching Telegram)
  are treated as late: power, confirm, lock, logout, Tailscale up/down, feature toggles and
  removing a user are **not executed**, and the message changes to
  `⌛ Ignored a button press that was queued while PREDATOR was offline. Press it again if you still want this.`
  with the button offered again. A late **Confirm** also discards that confirmation, so send the
  power command again. Navigation buttons and **Cancel** work normally.
- A burst of failed logins is rate-limited to 10 alerts per 10 minutes. The remainder is reported
  as one *FAILED LOGIN ALERTS SUPPRESSED* message (`N failed login attempts suppressed between
  HH:MM and HH:MM`) when the 10-minute window ends.

## Wrong times in messages (time zone)

Times in alerts are rendered in the PC's local time zone. The original event time is preserved, even
for alerts delivered late.

- Check *Settings → Time & language → Date & time*. Make sure **Set time zone automatically** is
  on, or that the right zone is selected.
- Check the clock is synchronised with `w32tm /query /status`.
- After changing the time zone, restart the service (`& $exe stop; & $exe start`) so that messages
  rendered from now on use the new zone.

## Power actions fail or are refused

- *Power Management is disabled.* Enable it in `/features`. This switch covers shutdown, restart,
  sleep, hibernate, **lock and logout**.
- *Hibernate is not available: …* Hibernation is turned off. Run `powercfg /a` to see what is
  available, and `powercfg /hibernate on` (elevated) to enable it if you want it.
- *Sleep is not available: …* Some PCs (Modern Standby / S0ix) do not support classic S3 sleep;
  `powercfg /a` shows which states exist.
- *Confirmation expired.* Shutdown, restart, sleep and hibernate must be confirmed within 60
  seconds (`confirm_timeout_secs` in `settings.json`). Send the command again. Only the person who
  asked can confirm it, and each confirmation works once.
- *Ignored a button press that was queued while PREDATOR was offline.* The press arrived late; see
  [Queue and offline behaviour](#queue-and-offline-behaviour).
- **Lock / logout** act immediately and need a signed-in user. With nobody signed in, the bot says
  so.

## Updating to a new version

1. Download the new `PredatorRemoteController.exe` (and check it against `SHA256SUMS.txt`, see
   [SmartScreen](#windows-protected-your-pc-smartscreen)).
2. Start it and confirm the UAC prompt. Because the program is installed, the management menu
   opens with an extra option `5  Update installed program to this version (x.y.z)`. It is shown
   only when the file you started differs from the installed one.
3. Choose **5** and confirm. The service and the tray icon stop for a few seconds, both files are
   replaced with verified copies, the service configuration of the new version is applied, and the
   new version starts. If it does not start, the previous version is restored:
   *Update failed: the new version did not start (…). The previous version was restored.*

Token, paired accounts, settings, the queue and a forced HTTPS transport are kept.

Unattended: `PredatorRemoteController.exe setup --yes` on an installed PC updates it when the file
differs, then prints the status.

- *The installed program is already this version.* Nothing to do.
- *The installed program folder is not protected, so it is not updated (…).* Uninstall (**7**,
  keep the data folder) and run setup again.
- *… is still in use; Windows deletes it at the next restart.* An old file was in use; it is
  removed at the next reboot.

## Uninstall leftovers

Run `PredatorRemoteController.exe` (or the installed copy without arguments), choose
**7 Uninstall** and confirm. It stops and removes the service, the tray icon and its autostart and
the program files, and restores the original logon audit policy. It then asks whether to delete
the data folder too (bot token, Telegram users, settings, logs); keep it to reinstall later with
the same bot and accounts.

The command-line `& $exe uninstall [--keep-audit-policy] [--purge-data]` removes the service and
the tray autostart but **leaves the program files** in `C:\Program Files\Predator`.

Possible leftovers:

- **`%ProgramData%\Predator`** is kept when you answered **No** to the data-folder question (or
  used `uninstall` without `--purge-data`). Delete it (elevated) with
  `Remove-Item "$env:ProgramData\Predator" -Recurse -Force`.
- **`%ProgramData%\Predator.untrusted-*`** folders were moved aside by setup because they could
  not be trusted. Uninstall does not touch them. Delete them by hand when you no longer need them.
- **Audit policy.** It is left as it is with `--keep-audit-policy`, or when the restore failed.
  When the restore fails (including when the saved values could not be trusted), uninstall ends
  with a warning — *the service was removed, but the original logon audit policy was NOT restored
  (…)* — everything else in the data folder is deleted when you chose to delete it, and
  `audit-backup.json` is kept there with the original values.
  - If you still have the exe, run `& $exe audit restore`. It deletes the backup only after the
    restore was verified.
  - Otherwise restore by hand. The values below are the Windows client defaults; use the values from
    the backup if they differ:

    ```powershell
    auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable  /failure:enable   # Logon
    auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable  /failure:disable  # Logoff
    auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable  # Other Logon/Logoff
    ```

    Never use `auditpol /clear` or `/restore`. They reset **all** audit settings, not just these.
- **Service "marked for deletion".** The service disappears once nothing holds a handle to it. Close
  *services.msc* and *Event Viewer*, or reboot.
- **Program folder kept.** Uninstall deletes only Predator's own files (`predator-service.exe`,
  `predator-tray.exe` and leftovers of interrupted updates). If you put other files in
  `C:\Program Files\Predator`, the folder and those files remain (*… was kept: it also contains …*).
  Files that are still in use, for example the installed copy when you started the uninstall from
  it, are deleted at the next restart (*In use, deleted at the next restart: …*).
- **Tray autostart.** If `PredatorTray` is still present, remove it with
  `Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PredatorTray`.
- **The bot itself** still exists in Telegram. Delete it in @BotFather (`/deletebot`) if you no
  longer need it.

## Dry-run mode (safe testing)

In dry-run mode the service **simulates** shutdown, restart, sleep, hibernate, lock, logout and
Tailscale up/down, and replies with what it would have done. Everything else works normally.

```powershell
New-Item -ItemType File -Path "$env:ProgramData\Predator\DRY_RUN" -Force | Out-Null
& $exe stop; & $exe start                       # dry-run is read at service start
```

The main menu and the status screen show a dry-run banner, and `status` prints a `DRY-RUN` line.
To return to normal operation:

```powershell
Remove-Item "$env:ProgramData\Predator\DRY_RUN"
& $exe stop; & $exe start
```

`"dry_run": true` in `settings.json` has the same effect. `predator-service.exe console ...` always
runs in dry-run mode, with or without the marker.

## High CPU, or repeated lines in the log

At idle the service should use practically no CPU (it is event-driven and does not poll). Measure
your own PC with the script from the repository (elevated):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure.ps1 -Seconds 300
```

If the monitor has trouble reading a log, it backs off instead of spinning: it reopens a log at
once at most once every 5 minutes, otherwise waits 5 seconds doubling to 10 minutes, and after 3
identical failures on every log it reopens them all together. Look for these lines in
`predator.log`:

| Line | Meaning |
|---|---|
| `Cannot read the <log> log: … (error N); retrying` | A read failed; the monitor reopens or retries with backoff |
| `… subscription was signalled 3 times without new records; resubscribing` | A subscription looked stuck and was reopened |
| `login monitor: every monitored event log keeps failing with error N (…); closing all subscriptions and reopening them together in S s` | Every log failed the same way 3 times; all were closed for a shared backoff |
| `login monitor: reopening all event-log subscriptions together` | The shared backoff is over |
| `Windows Event Log service restarted (PID a → b); resubscribing from the saved positions` | The EventLog service restarted; normal recovery |
| `… monitoring <log> again (after: …)` | The log worked for 5 minutes again; the incident is over |

**Repeated lines.** The log protects itself from loops: identical consecutive lines within
60 seconds are written once and followed by `… previous message repeated N times` (with
`(last at HH:MM:SS)` when the summary is written later), and each place in the code can write at
most 200 lines per minute, after which you see
`rate limit: N more line(s) from <file:line> were not logged in the previous minute (limit 200 per minute)`.
A few repeats are harmless. A `rate limit` line, or a repeat count in the thousands, points to a
loop: note the line that is repeated, measure the CPU as shown above, and collect diagnostics
(below). `security.log` is not affected by these limits.

**Memory figures that change by themselves.** One to two minutes after the start (once Telegram
has answered), and again after a burst of commands, the service's working set drops sharply. That
is deliberate: it releases its heap caches and gives back the pages it needed only for that work.
Pages that are used again come back, mostly from memory, so the working set then grows a little.
This is neither a leak nor a fault. The trim never runs on a timer, so an idle service is not woken
for it. Private memory is the steadier figure to compare; `status` shows both.

## Collecting diagnostics

1. In an elevated PowerShell:

   ```powershell
   & $exe version
   & $exe status
   & $exe selftest
   & $exe audit status
   & $exe features list
   netsh winhttp show proxy
   Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\PredatorRemoteController' -Name Environment -ErrorAction SilentlyContinue |
       Select-Object -ExpandProperty Environment     # a forced HTTPS transport, if any
   Get-Content "$data\logs\predator.log" -Tail 200 | Set-Content "$env:USERPROFILE\Desktop\predator-log.txt"
   Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'PredatorRemoteController' } -MaxEvents 20 -ErrorAction SilentlyContinue |
       Format-List TimeCreated, Message
   ```

2. Optional: run `scripts\measure.ps1` from the repository for CPU and memory figures.

**Never share** `token.dat`, your bot token or `settings.json` unredacted. `settings.json` contains
the numeric ids and names of every paired Telegram account and the bot's username. Logs are
token-redacted and never contain pairing codes, but review them before posting them anywhere: they
contain the computer name, Windows and Telegram user names, Telegram user ids and IP addresses.
Replace them with placeholders (for example `DESKTOP-01`, `alex`, `123456789`, `192.168.1.x`).
