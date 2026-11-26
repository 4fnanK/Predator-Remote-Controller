# Predator Remote Controller

[![CI](https://github.com/4fnanK/Predator-Remote-Controller/actions/workflows/ci.yml/badge.svg)](https://github.com/4fnanK/Predator-Remote-Controller/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/4fnanK/Predator-Remote-Controller)](https://github.com/4fnanK/Predator-Remote-Controller/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Watch and control your Windows PC from a private Telegram bot. Predator Remote Controller is a
small native Windows service, written in Rust and shipped as one ~2.6 MB file. It sends you an
instant Telegram alert when someone signs in to the PC, whether at the keyboard, over Remote
Desktop or over SSH. From your phone you can then check the PC, lock it, shut it down, and, most
usefully, **turn Tailscale on and off**, which makes the PC reachable for Remote Desktop and SSH
from anywhere without port forwarding. At idle it uses about 2.4 MB of private memory and
practically no CPU.

Licensed under the [MIT License](LICENSE).

---

## Contents

- [Features](#features)
- [Why Tailscale?](#why-tailscale)
- [Quick start](#quick-start)
- [Management menu](#management-menu)
- [Telegram bot: commands and buttons](#telegram-bot-commands-and-buttons)
- [Alerts](#alerts)
- [Chat auto-clean](#chat-auto-clean)
- [Offline behaviour](#offline-behaviour)
- [Multiple users and pairing](#multiple-users-and-pairing)
- [Tray icon](#tray-icon)
- [Command-line reference](#command-line-reference)
- [Settings](#settings)
- [Files and locations](#files-and-locations)
- [Resource usage](#resource-usage)
- [Security](#security)
- [Building from source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Real-time login alerts:** Windows sign-ins and unlocks, Remote Desktop connects, reconnects
  and disconnects, sign-outs, failed sign-ins, SSH logins, failed SSH logins, closed SSH
  sessions, and a clearing of the Security log. The alerts come from the Windows Security log
  (events 4624, 4625, 4634, 4647, 4778, 4779 and 1102) and the OpenSSH event logs.
- **Remote control from Telegram:** system status, network, battery and login history. Lock and
  log off run at once. Shutdown, restart, sleep and hibernate wait for a one-time confirmation
  button.
- **Tailscale on demand:** **Up** starts the Tailscale service and app and connects them.
  **Down** disconnects them and closes them again.
- **Several Telegram accounts:** up to 20 accounts with the roles *Admin* or *User*. Each one is
  added with a one-time 8-digit pairing code that is created on the PC.
- **Works offline:** while the PC has no internet, alerts are kept on disk and delivered later
  with their original time. Commands and button presses that arrive late are not carried out.
- **Tidy chat:** menus and replies delete themselves. Login, logout and security alerts stay.
- **Nine feature switches,** which you can change from Telegram, the tray icon or the command line.
- **Tray icon** for the signed-in user, with status, feature toggles and pairing.
- **One file with guided setup:** double-click, confirm the UAC prompt, paste the bot token, pair
  your account. Run the file again for the management menu: update, change the token, manage
  users, uninstall.
- **Light:** no Electron, no .NET, no async runtime and no bundled TLS library. Everything is
  event-driven, with about 5 wake-ups per minute at idle.
- **Built with security in mind:** there is no remote shell. Telegram input never reaches a shell
  or a command line. The bot token is encrypted with DPAPI, accounts are recognised by their
  numeric Telegram ID, and the bot only works in private chats.

---

## Why Tailscale?

Telegram is good for alerts and buttons, but it cannot show you the PC's desktop or give you a
shell. [Tailscale](https://tailscale.com) can. It puts the PC on your own private, encrypted
network (your *tailnet*) under a stable address, such as `100.64.0.5` or the MagicDNS name
`desktop-01`. Your phone and laptop can reach that address from anywhere, for example over mobile
data, hotel Wi-Fi or another office's network. You do not need port forwarding on the router, and
Remote Desktop and SSH are never exposed to the internet.

Predator turns Tailscale into a switch you can flip from your phone. Starting Tailscale from
Telegram is the main reason the bot exists:

1. When you need the PC, tap **🛡 Tailscale → ▶️ Up**, or send `/tailscale up`.
2. Predator then does the following:
   - starts the `Tailscale` Windows service;
   - starts the Tailscale app (`tailscale-ipn.exe`) in the signed-in user's session if it is not
     running;
   - waits until Tailscale is ready and runs a plain `tailscale up`, which leaves your Tailscale
     settings unchanged;
   - replies with every step and the PC's Tailscale IP.
3. Connect with **Remote Desktop** or **SSH** to that address.
4. When you are done, tap **⏹ Down**, or send `/tailscale down`. Predator then:
   - disconnects;
   - closes the Tailscale app;
   - stops the Tailscale service and checks that `tailscaled.exe` has exited.

   The PC then leaves your tailnet, and Tailscale uses no resources until you need it again.

Up and Down run at once, without a confirmation, and only one of them runs at a time. The bot
keeps answering other commands while they run. Telegram itself does not depend on Tailscale, so
you can always bring Tailscale up again.

### Connecting over Tailscale

| | Remote Desktop (RDP) | SSH |
|---|---|---|
| On the PC | Windows **Pro, Enterprise or Education** (Windows Home cannot accept RDP connections), and **Settings → System → Remote Desktop** switched on | The optional Windows feature **OpenSSH Server**, with the `sshd` service running |
| On your phone or laptop | The Tailscale app, signed in to the same tailnet, and an RDP client (Windows App / Remote Desktop) | The Tailscale app and any SSH client |
| Connect to | `desktop-01` or `100.64.0.5` | `ssh alex@desktop-01` |

```powershell
mstsc /v:desktop-01          # Remote Desktop from another Windows PC
ssh alex@desktop-01          # SSH with the Windows account name of the PC
ssh alex@100.64.0.5          # the same, using the Tailscale IP
```

You sign in with a Windows account of the PC (its password, or an SSH key). Every connection like
this also produces a login alert (🔐 NEW WINDOWS LOGIN with *Login Method: Remote Desktop*, or
🔐 NEW SSH LOGIN), and so would anybody else's connection.

### Recommended: Run unattended

In the Tailscale app, choose **Preferences → Run unattended**.

- **Without it,** Tailscale on Windows only connects while a user is signed in, because the
  Tailscale app does the connecting. With nobody signed in, Up can start the service but cannot
  connect.
- **With it,** Tailscale (and `/tailscale up` from Telegram) also works when nobody is signed in to
  Windows, for example after a reboot or a power cut.

### Before the first Up

- Install [Tailscale for Windows](https://tailscale.com/download/windows) and sign in once on the
  PC. Predator never signs in for you.
  - If Tailscale still needs a login, the bot shows the login link. Whoever opens that link binds
    the PC to *their* tailnet, so only open it yourself.
  - If your tailnet requires device approval, approve the PC in the Tailscale admin console.
- At the end of the setup, Predator checks Tailscale and tells you what is missing. The setup only
  reads the Tailscale status; it never runs Up or Down.
- Down stops the Tailscale service for every user of the PC. It does not change the service's
  startup type, so Tailscale normally starts with Windows again after a reboot.
- Up and Down need the *Tailscale Management* feature, which is on by default.

---

## Quick start

### Requirements

- Windows 10 or 11, 64-bit, and an administrator account for the setup.
- A Telegram account.
- Optional:
  - [Tailscale](https://tailscale.com/download/windows), for remote access;
  - the **OpenSSH Server** feature, for SSH access and SSH alerts;
  - Windows Pro, Enterprise or Education, for incoming Remote Desktop connections.

### 1. Download and check the file

Open the [latest release](https://github.com/4fnanK/Predator-Remote-Controller/releases/latest)
and download both files:

| File | What it is |
|---|---|
| `PredatorRemoteController.exe` | The whole program in one file: service, setup and tray icon |
| `SHA256SUMS.txt` | SHA-256 checksums of the release files |

Check the download in PowerShell:

```powershell
cd $HOME\Downloads
Get-FileHash .\PredatorRemoteController.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The hash must equal the one on the `PredatorRemoteController.exe` line of `SHA256SUMS.txt`
(upper or lower case does not matter). You can also compare them in one step; `True` means the file
is intact:

```powershell
$expected = ((Select-String -Path .\SHA256SUMS.txt -Pattern 'PredatorRemoteController\.exe').Line -split '\s+')[0]
(Get-FileHash .\PredatorRemoteController.exe -Algorithm SHA256).Hash -eq $expected
```

> **Windows SmartScreen.** The program is not code-signed, so Windows may show *"Windows protected
> your PC"* when you start it. Once you have checked the hash, click **More info → Run anyway**.

### 2. Create your bot

1. In Telegram, open **[@BotFather](https://t.me/BotFather)**. It is the official bot and has a
   blue check mark.
2. Send `/newbot`. Choose a display name, then a username that ends in `bot`, such as
   `YourPcBot`.
3. BotFather replies with a token that looks like `123456789:AAH...`. Copy it and keep it secret.
4. Recommended: send `/setjoingroups` and choose **Disable**, so nobody can add the bot to a group.

The full guide, including how to replace a token that leaked, is in
[docs/TELEGRAM_SETUP.md](docs/TELEGRAM_SETUP.md).

### 3. Run the setup

Double-click `PredatorRemoteController.exe`. It asks for administrator rights with the usual
User Account Control (UAC) prompt and then continues in a new console window. If you decline the
prompt, nothing on the PC is changed.

The setup first shows where it will put its files and asks `Install now? [Y/n]`. It then runs
six steps:

| Step | What happens |
|---|---|
| **[1/6] Telegram bot token** | Shows a short BotFather guide and asks for the token. Your typing is hidden. Predator checks the token with Telegram and shows the bot it belongs to, for example `OK - this is the token of @YourPcBot (Your PC)`. You get up to 5 attempts, and pressing Enter alone cancels. If a token from an earlier installation is still stored, you are asked whether to keep it. |
| **[2/6] Protected data folder** | Creates `%ProgramData%\Predator`, which only SYSTEM and Administrators can open, and stores the token there, encrypted with Windows DPAPI. An existing folder that cannot be trusted is moved aside and never used. |
| **[3/6] Link your Telegram account** | Shows a one-time pairing code and a link (see below). The account that uses it becomes the first **Admin**. If pairing fails, you can try again or continue without an account and pair later from the menu. If accounts from an earlier installation are still there, you are asked whether to pair another one. |
| **[4/6] Program files** | Copies the program to `C:\Program Files\Predator\predator-service.exe` and writes the tray program `predator-tray.exe`, which is built into the file, next to it. Both files are checked with SHA-256. Only administrators can change that folder. |
| **[5/6] Windows service** | Registers and starts the `PredatorRemoteController` service. Details are listed below this table. |
| **[6/6] Tray icon and Tailscale** | Starts the tray icon in your session, without administrator rights. Then explains why Tailscale matters, checks its state (not installed, not logged in, connected …) and gives the *Run unattended* tip. |

In step 5, the setup:

- registers the service with automatic start under LocalSystem. Windows restarts it after 5, 10 or
  30 seconds if it ever crashes;
- makes your Windows account the owner of the tray icon;
- turns on the logon audit policy that login alerts need. The previous policy is saved and put back
  when you uninstall;
- sets the tray icon to start for every user who signs in.

The pairing step looks like this:

```
Pairing code:  1234 5678
Valid for:     10 min (until 14:35), single use
Role:          Admin

On the phone with the Telegram account to add:
  - open this link and press Start:   https://t.me/YourPcBot?start=pair-12345678
  - or send this message to @YourPcBot:   /pair 12345678
```

On your phone, either open the link and tap **Start**, or send `/pair 1234 5678` to your bot (the
space is optional). The bot answers `✅ Paired with DESKTOP-01. Send /menu to start.` and the setup
continues.

At the end, the setup prints a summary and waits for Enter:

```
==================== Summary ====================
Program folder : C:\Program Files\Predator
Data folder    : C:\ProgramData\Predator (SYSTEM + Administrators only)
Service        : running (starts automatically with Windows)
Telegram bot   : @YourPcBot
Telegram users : alex (123456789, Admin)
Tray icon      : started (not elevated)
Tailscale      : connected (100.64.0.5)

Next: open your bot in Telegram and send /menu.
```

If a step fails, the setup explains why and stops. Nothing is rolled back: fix the problem and run
the program again, and it continues where it stopped.

**Unattended installation.** Run this from an elevated PowerShell. You need a text file that holds
only the token, and your numeric Telegram user ID:

```powershell
.\PredatorRemoteController.exe setup --token-file C:\path\token.txt --telegram-id 123456789 --yes
```

Delete the token file afterwards. With `--yes` the setup never asks a question. On a PC where
Predator is already installed, the same command updates the program to this version and applies
the given token and user.

### 4. First steps in Telegram

1. Send `/menu` to your bot. You get the control panel described in
   [Telegram bot: commands and buttons](#telegram-bot-commands-and-buttons).
2. Lock the PC and unlock it. A 🔐 NEW WINDOWS LOGIN alert arrives.
3. Alerts for failed sign-ins are **off by default**, because they can be noisy. Turn them on under
   **⚙️ Features → Failed Logins**.

---

## Management menu

Start `PredatorRemoteController.exe` again (or `C:\Program Files\Predator\predator-service.exe`)
and confirm the UAC prompt. On a PC where Predator is already installed, you get this menu instead
of the setup:

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

| Option | What it does |
|---|---|
| **1 Status** | Shows the service details: state, version and uptime; Telegram connection and bot; which HTTPS transport is used; login and SSH monitors; queued alerts; memory use; feature switches. Also shows the program and data folders, plus the Tailscale state with advice. |
| **2 Pair a Telegram user** | Asks `Make this account an Admin (can also remove users)? [y/N]`. Then shows a one-time code and link that are valid for 10 minutes, and waits until the new account has used them. Ctrl+C cancels the code. See [Multiple users and pairing](#multiple-users-and-pairing). |
| **3 Telegram users (list / remove)** | Lists every paired account: ID, role, date added and name. To remove one, type its numeric ID and confirm. That account loses access at once, and the other users are told. The last admin cannot be removed. |
| **4 Change bot token** | Asks for a new token, checks it with Telegram and stores it encrypted. If the service is running, offers to restart it so it uses the new token. Paired users stay paired. If the new token belongs to a **different** bot, everybody must open the new bot and tap **Start** once, or Telegram cannot deliver its messages. |
| **5 Update installed program to this version (x.y.z)** | Only shown when the file you started differs from the installed one, for example a newer download. See [Updating](#updating). |
| **6 Open the bot in Telegram** | Opens `https://t.me/YourPcBot` in your browser. |
| **7 Uninstall** | Asks for confirmation, then removes Predator. See [Uninstalling](#uninstalling). |
| **0 Exit** | Closes the menu (`q` and `exit` work too). |

### Updating

Download the new `PredatorRemoteController.exe`, start it and choose
**5 Update installed program to this version**. The update then:

1. copies the new files next to the old ones and checks them;
2. stops the service and the tray icons for a few seconds;
3. swaps the files and applies the new version's service configuration;
4. starts the service and the tray icon again.

If the service was running before and the new version does not start, the previous version is
restored automatically. Your token, users, settings and history are kept, because the data folder
is not touched.

### Uninstalling

**7 Uninstall** first asks `Uninstall Predator Remote Controller? [y/N]`, then
`Also delete the data folder (bot token, Telegram users, settings, logs)? [y/N]`.

It removes:

- the Windows service;
- the running tray icons and the tray autostart;
- the program files in `C:\Program Files\Predator`.

It also puts back the logon audit policy that was saved during the setup.

It keeps:

- the data folder `%ProgramData%\Predator`, unless you chose to delete it. It holds the token,
  users, settings, history and logs, so you can reinstall later without pairing again;
- the downloaded `PredatorRemoteController.exe`;
- any `%ProgramData%\Predator.untrusted-*` folder that the setup moved aside. Delete it yourself
  when you no longer need it;
- everything else on the PC: Tailscale, OpenSSH, the Remote Desktop settings and all other
  services.

If the audit policy cannot be put back, the uninstall says so. The saved values then stay in
`audit-backup.json`, and you can restore them later with
`predator-service.exe audit restore` from an elevated prompt.

---

## Telegram bot: commands and buttons

The bot only works in **private chats** with paired accounts (see
[Multiple users and pairing](#multiple-users-and-pairing)). Every paired account can use every
command. Admins can also remove other accounts.

A few general rules:

- Commands also work with the bot's name attached, for example `/status@YourPcBot`. The command
  list is registered with Telegram automatically, so it appears in the `/` menu.
- Buttons update the message they belong to. Slash commands send a new message.
- An edited message is never carried out.
- Plain text gets the hint `ℹ️ I only understand commands. Open the control panel with /menu or
  see /help.` with an **[🏠 Open Menu]** button.
- An unknown command gets `❓ Unknown command. Send /help for the list.`

### Commands

| Command | What it does | Confirmation | Needs feature |
|---|---|---|---|
| `/menu`, `/start` | Opens the control panel (main menu) | No | — |
| `/status` | System status: computer, Windows version, uptime, service memory and CPU time, Telegram and monitor state, audit policy, queued and delivered alerts, signed-in sessions | No | — |
| `/network` | Connection type, Wi-Fi name (SSID), IP address, internet state, VPN | No | Network Information |
| `/battery` | Battery level, charging state, AC power, time left, battery saver | No | Battery Information |
| `/history` | The last 10 login events (Windows and SSH) | No | — |
| `/features` | The feature switches, with toggle buttons | No | — |
| `/tailscale` or `/tailscale status` | The Tailscale screen with **Up** and **Down** buttons | No | Tailscale Management |
| `/tailscale up` | Starts the Tailscale service and app if needed and connects | No | Tailscale Management |
| `/tailscale down` | Disconnects, closes the Tailscale app and stops the Tailscale service | No | Tailscale Management |
| `/lock` | Locks every active session, at once | No | Power Management |
| `/logout` | Logs off the active user, at once | No | Power Management |
| `/shutdown` | Shuts the PC down 5 seconds after you confirm | **Yes** | Power Management |
| `/restart` | Restarts the PC 5 seconds after you confirm | **Yes** | Power Management |
| `/sleep` | Puts the PC to sleep after you confirm | **Yes** | Power Management |
| `/hibernate` | Hibernates the PC after you confirm | **Yes** | Power Management |
| `/cancel` | Cancels your pending power confirmation. It does not stop a shutdown that has already started. | No | — |
| `/clear` | Deletes menus, replies and your own commands from this chat at once. Login, logout and security alerts stay. | No | — |
| `/users` | Lists the paired Telegram accounts. Admins also get remove buttons. | No | — |
| `/pair CODE` | Pairs a **new** account with a code created on the PC. An account that is already paired gets `ℹ️ You are already paired.` | No | — |
| `/help` | All commands, the confirmation rules and the security rules | No | — |

Only shutdown, restart, sleep and hibernate ask for a confirmation. That is deliberate: lock,
logout, Tailscale Up/Down, feature switches and removing a user all happen at once.

If a feature is switched off, its commands and buttons reply with, for example,
`🚫 Battery Information is disabled. Enable it in /features.` and offer the buttons
**[⚙️ Features] [⬅️ Back]**.

### Main menu (`/menu`)

```
🖥 PREDATOR REMOTE CONTROL
━━━━━━━━━━━━━━━━━━
🟢 Online · DESKTOP-01
⏱ Uptime: 3h 12m · Service: 3h 11m
🔐 Login monitor: 🟢 Active · SSH: 🟢 Active
📬 Queued alerts: 0

[📊 System Status]
[🌐 Network]        [🔋 Battery]
[📜 Login History]  [⚙️ Features]
[⏻ Shutdown]        [🔄 Restart]
[💤 Sleep]          [🌙 Hibernate]
[🔒 Lock]           [🚪 Logout]
[🛡 Tailscale]
[❓ Help]
```

| Button | What it does | Confirmation |
|---|---|---|
| 📊 System Status | Opens the status screen (same as `/status`) | No |
| 🌐 Network | Opens the network screen (same as `/network`) | No |
| 🔋 Battery | Opens the battery screen (same as `/battery`). A PC without a battery shows `🔌 No battery detected — this PC runs on AC power.` | No |
| 📜 Login History | Shows the last 10 login events, newest first | No |
| ⚙️ Features | Opens the feature switches | No |
| ⏻ Shutdown | Opens the shutdown confirmation | **Yes** |
| 🔄 Restart | Opens the restart confirmation | **Yes** |
| 💤 Sleep | Opens the sleep confirmation | **Yes** |
| 🌙 Hibernate | Opens the hibernate confirmation | **Yes** |
| 🔒 Lock | Locks every active session at once and reports the result | No |
| 🚪 Logout | Logs off the active user at once and reports the result | No |
| 🛡 Tailscale | Opens the Tailscale screen | No |
| ❓ Help | Opens the help screen | No |

In dry-run mode, the header also shows
`🧪 DRY-RUN mode — power, lock, logout and Tailscale up/down are simulated.` (see
[Settings](#settings)).

### Status, Network, Battery and Login History screens

Each of these screens has two buttons:

| Button | What it does |
|---|---|
| 🔄 Refresh | Reads the information again and updates the message |
| ⬅️ Back | Returns to the main menu |

Network example:

```
🌐 NETWORK STATUS

Connection: Wi-Fi
SSID: HomeNetwork
IP Address: 192.168.1.20
Internet: 🟢 Connected
```

The Wi-Fi name is looked up only when you ask for it, in a short-lived helper process. It works
without the Windows location permission. Wi-Fi BSSIDs and scan results are never collected.

### Features screen

The screen lists all nine features with 🟢 (on) or 🔴 (off), followed by one toggle button per
feature, two per row, and **[⬅️ Back]**. A tap switches the feature at once and shows a short
notice such as *SSH Monitoring disabled*. No confirmation is needed.

| Button | Feature (`settings.json` key) | Default | When it is off |
|---|---|---|---|
| Login Monitor | Windows Login Monitoring (`login_monitoring`) | On | Windows logon events are ignored completely: no history, no alerts |
| SSH Monitor | SSH Monitoring (`ssh_monitoring`) | On | OpenSSH events are ignored completely |
| Login Alerts | Login Notifications (`login_notifications`) | On | Successful Windows and SSH logins are recorded in the history but not sent |
| Failed Logins | Failed Login Notifications (`failed_login_notifications`) | **Off** | Failed Windows and SSH logins are recorded but not sent |
| Logout Alerts | Logout Notifications (`logout_notifications`) | On | Sign-outs, disconnects and closed SSH sessions are recorded but not sent |
| Power | Power Management (`power_management`) | On | Shutdown, restart, sleep, hibernate, lock and logout are refused |
| Network | Network Information (`network_info`) | On | `/network` is refused |
| Battery | Battery Information (`battery_info`) | On | `/battery` is refused |
| Tailscale | Tailscale Management (`tailscale_management`) | On | `/tailscale` and its buttons are refused |

`/features` keeps working even when every other feature is off.

### Tailscale screen

```
🛡 TAILSCALE

Installed: ✅ Yes (v1.xx.x)
Service: Running
App: 🟢 Running
Connection: 🟢 Connected
Tailscale IP: 100.64.0.5
Hostname: desktop-01
Tailnet: example.ts.net

[▶️ Up]       [⏹ Down]
[🔄 Refresh]  [⬅️ Back]
```

| Button | What it does | Confirmation |
|---|---|---|
| ▶️ Up | Same as `/tailscale up`: starts the service and the app, connects, then reports each step and the new status | No |
| ⏹ Down | Same as `/tailscale down`: disconnects, closes the app, stops the service, then reports each step | No |
| 🔄 Refresh | Reads the Tailscale status again | No |
| ⬅️ Back | Returns to the main menu | No |

- **Up** and **Down** are only shown when Tailscale is installed.
- While Up or Down runs, the message shows `⏳ Bringing Tailscale up…` or
  `⏳ Bringing Tailscale down…`. It then changes to `✅ Tailscale up completed` or
  `❌ Tailscale up failed`, with the steps and the current status.
- A second request while one is running gets `⏳ A Tailscale operation is already running.`
- When Tailscale needs a login, the screen shows the login link, with the warning that whoever
  opens it binds this PC to their tailnet.

### Power confirmation

```
⚠️ CONFIRM SHUTDOWN

🖥 Computer: DESKTOP-01
Open apps will be closed. Unsaved work may be lost.
⏳ Expires in 1 minute.

[✅ Confirm Shutdown]  [❌ Cancel]
```

| Button | What it does |
|---|---|
| ✅ Confirm *Action* | Carries out the action. For shutdown or restart, the message changes to `✅ Shutdown initiated — DESKTOP-01 will power off in 5 seconds.` For sleep or hibernate, it changes to `💤 DESKTOP-01 is going to sleep now.` or `🌙 DESKTOP-01 is hibernating now.` |
| ❌ Cancel | Discards the request: `❌ Shutdown cancelled.` |

How confirmations behave:

- A confirmation expires after 60 seconds (`confirm_timeout_secs`). After that, pressing Confirm
  shows `⌛ Confirmation expired. Send /shutdown again.`
- A confirmation works once. Only the account that asked for it can confirm or cancel it. A used,
  replaced or unknown confirmation is answered with *"This confirmation is no longer valid."*
- Each account has at most one pending confirmation. A new power request replaces the old one,
  and the old message changes to *"Superseded"*.
- `/cancel`, `/clear` and removing that account all discard a pending confirmation.
- An action is refused when Power Management is off, or when Windows reports it as unavailable.
  For example, if hibernation is disabled you get `❌ Hibernate is not available: …`.

### Users screen (`/users`)

```
👥 TELEGRAM USERS (2 of 20)

👑 alex · 123456789 · Admin · added 27 Nov 2026 (you)
👤 sam · 987654321 · User · added 27 Nov 2026

[🗑 Remove sam]
[🔄 Refresh]  [⬅️ Back]
```

| Button | Who sees it | What it does | Confirmation |
|---|---|---|---|
| 🗑 Remove *name* | Admins only, one button for every **other** account | Removes that account at once. Everyone else gets a 🗑 TELEGRAM USER REMOVED notice. | No |
| 🔄 Refresh | Everyone | Reloads the list | No |
| ⬅️ Back | Everyone | Returns to the main menu | No |

An admin cannot remove their own account here, and the last admin can never be removed.

### Help screen

`/help` and **❓ Help** list every command and explain the confirmation and security rules. The
screen has one button, **[⬅️ Back]**.

### Late commands and button presses

- **Late commands.** A command that changes something (`/shutdown`, `/restart`, `/sleep`,
  `/hibernate`, `/lock`, `/logout`, `/tailscale up`, `/tailscale down`) is ignored when it is
  older than 5 minutes (`stale_command_secs`), because it was probably sent while the PC was
  offline. The bot replies, for example,
  `⌛ Ignored /lock sent at 14:02:11 — older than 5 minutes (sent while the PC was offline?)`.
- **Late button presses.** A button press carries no time stamp. Telegram may deliver presses it
  kept while Predator was not listening, that is, in the first batch after a start or after more
  than 90 seconds without contact. Such presses are not carried out if they would change
  something: power, Confirm, lock, logout, Tailscale Up/Down, feature switches or removing a user.
  The message changes to `⌛ Ignored a button press that was queued while PREDATOR was offline.
  Press it again if you still want this.` and offers the button again. Navigation buttons and
  Cancel keep working as usual.

---

## Alerts

Every paired account receives every alert. All alerts use the same layout. Here is an example of
a Remote Desktop sign-in made over Tailscale:

```
🔐 NEW WINDOWS LOGIN

🖥 Computer: DESKTOP-01
👤 User: alex
🔑 Login Method: Remote Desktop
🌍 Source IP: 100.64.0.7
💻 Client: LAPTOP-02
🕒 Time: 14:30:25 · 27 Nov 2026
✅ Status: Successful
```

An alert that was delivered more than a minute after its event gets a note such as
`📨 Delivered late — queued while offline (sent 15:02:11)`.

**Login alerts.** These are always kept in the chat.

| Alert | When |
|---|---|
| 🔐 NEW WINDOWS LOGIN | Sign-in at the PC, unlock, Remote Desktop connect or reconnect, sign-in with cached credentials |
| ⚠️ FAILED WINDOWS LOGIN | A failed Windows sign-in, with the reason. Off by default; turn on *Failed Logins*. |
| 🚪 WINDOWS LOGOUT | Sign-out, or Remote Desktop disconnect |
| 🔐 NEW SSH LOGIN | Successful SSH login, with the source IP, authentication method and key fingerprint |
| ⚠️ FAILED SSH LOGIN | Failed SSH login, or too many authentication attempts. Off by default, like failed Windows logins. |
| 🚪 SSH SESSION CLOSED | End of an SSH session |
| ⚠️ FAILED LOGIN ALERTS SUPPRESSED | Sent when more than 10 failed-login alerts (Windows and SSH together) would be sent within 10 minutes. It replaces the extra alerts with one count. |

**Security alerts.** These are always kept in the chat.

| Alert | When |
|---|---|
| 🚨 UNAUTHORIZED ACCESS ATTEMPT | An unpaired Telegram account wrote to the bot. The alert shows its ID, username, name and the start of the message, at most once per hour per account. |
| 🚨 SECURITY LOG CLEARED | Somebody erased the Windows Security log (event 1102) |
| 👤 NEW TELEGRAM USER PAIRED | A new account was paired. Sent to everyone except the new account. |
| 🗑 TELEGRAM USER REMOVED | An account was removed. Sent to everyone who is left. |

**Status notices.** These are deleted automatically, see [Chat auto-clean](#chat-auto-clean).

| Notice | When |
|---|---|
| 🟢 PREDATOR ONLINE | The service started, with its version and the boot time |
| 🔴 PREDATOR GOING OFFLINE | The service is stopping, with the reason (*System shutdown* or *Service stopped*) and its uptime |
| ☀️ PREDATOR RESUMED | The PC woke up from sleep or hibernation |
| ⚙️ FEATURE CHANGED | A feature was switched from the tray icon or the command line |
| ⚠️ AUDIT POLICY INSUFFICIENT | The Windows logon audit policy no longer records what login alerts need. The notice tells you how to fix it. |
| ⚠️ LOGIN MONITOR GAP | An event log was cleared or rolled over while it was not being read, so some events may be missing |

The online, offline and resumed notices can be turned off with `lifecycle_notifications` (see
[Settings](#settings)). For example:

```
🟢 PREDATOR ONLINE

Computer: DESKTOP-01
Event: Service started
Version: 1.0.0
Boot time: 27 Nov 2026, 08:00:12
🕒 Time: 08:00:41 · 27 Nov 2026
```

---

## Chat auto-clean

The chat keeps only the messages worth looking back at.

| Kept | Deleted automatically |
|---|---|
| Windows and SSH logins, logouts, closed sessions and failed logins, and the *suppressed* summary | Menus, status screens and all other bot replies |
| Security alerts: unauthorized access attempt, Security log cleared, user paired, user removed | Results of commands such as lock, Tailscale Up/Down or feature switches |
| | Power confirmations, once they can no longer be confirmed |
| | Status notices (online, going offline, resumed, feature changed, audit policy, monitor gap) |
| | Your own commands and texts in the bot chat |

Messages are deleted:

- **when you send something new.** The earlier messages go once the reply to the new message has
  been sent. A power confirmation that can still be confirmed is the only exception;
- **after a time without use,** 10 minutes by default (`chat_clean_after_secs`). Pressing a button
  on a menu restarts its timer;
- **when you send `/clear`.** Everything that would be cleaned goes at once, including the `/clear`
  message itself and a pending power confirmation. `/clear` sends no reply.

Each account has its own chat with the bot, and cleaning one chat never touches another.

Telegram does not let bots delete messages older than 48 hours, so older ones stay. Messages from
before Predator was installed are not known to it; clear them once with Telegram's
**Clear history**. To turn the feature off, set `auto_clean_chat` to `false`.

---

## Offline behaviour

- Every alert is written to `queue.json` on disk before anything else happens, so a crash or a
  power cut does not lose it. While the PC has no internet, alerts wait in the queue and are
  delivered in order when the connection returns. Each one keeps its original time and gets a
  *delivered late* note.
- At worst an alert can arrive twice after a crash. It is never lost.
- The queue holds at most 1000 alerts; beyond that, the oldest are dropped.
- A network change or a wake-up from sleep makes Predator reconnect at once.
- Commands and button presses that Telegram kept while the PC was offline are handled as described
  in [Late commands and button presses](#late-commands-and-button-presses). Read-only commands
  are still answered.
- Alerts that happen before any account is paired wait in the queue until one is.

---

## Multiple users and pairing

Up to **20** Telegram accounts can use the bot. Access is decided by the numeric Telegram user ID
only; names are only for display. Every paired account receives every alert and can use every
command.

| Role | Can do |
|---|---|
| **Admin** | Everything, and remove other accounts with `/users` |
| **User** | Every command and button |

The first account that is paired is always an Admin.

### Adding another Telegram account

New accounts are added **only** with a one-time pairing code created on the PC. You can create
one in three places:

| Where | How | Role of the new account |
|---|---|---|
| Tray icon | **Pair Telegram User…**. A window shows the code and a link, and a notification appears when the account has paired. | User. The first account of an empty list becomes Admin. |
| Management menu | **2 Pair a Telegram user**. You are asked whether the account should be an Admin. | Admin or User |
| Command line (elevated) | `PredatorRemoteController.exe pair [--admin] [--ttl SECS]`, or the installed `predator-service.exe pair …` | Admin with `--admin`, otherwise User |

On their own phone, the new person then does one of two things:

- opens the link `https://t.me/YourPcBot?start=pair-12345678` and taps **Start**; or
- sends `/pair 1234 5678` to the bot in a private chat.

The bot answers `✅ Paired with DESKTOP-01. Send /menu to start.` Everyone else gets a
👤 NEW TELEGRAM USER PAIRED notice.

### Removing an account

| Where | How |
|---|---|
| Telegram | An Admin sends `/users` and taps **🗑 Remove *name***. This takes effect at once, without a confirmation. |
| Management menu | **3 Telegram users (list / remove)**, then type the ID |
| Command line (elevated) | `predator-service.exe users remove 123456789` |

The removed account loses access with its next message, and any pending confirmation it had is
discarded. Everyone who is left gets a 🗑 TELEGRAM USER REMOVED notice.

In an emergency, `predator-service.exe set-owner --telegram-id 123456789` removes **every** account
and keeps only that one, as Admin.

### Limits and protections

- **The code.** A code has 8 random digits and works once. It is valid for 10 minutes by default;
  the command line accepts 60 to 3600 seconds with `--ttl`. Only one code is active at a time, and
  a new code replaces the previous one.
- **Guessing.** A code becomes invalid after 5 wrong attempts in total. On top of that, each
  Telegram account gets at most 5 wrong attempts per hour, across all codes. Codes are compared
  in constant time.
- **No hints.** A failed attempt gets the same reply as any other stranger's message
  (`⛔ Access denied. This bot is private.`, at most once per hour). An outsider cannot even tell
  whether a code is active.
- **No traces.** Codes exist only in memory and are never sent to Telegram by the PC or written to
  a log. Restarting the service cancels an open pairing.
- **Elevation.** Creating an *Admin* code and removing accounts from the PC need an elevated
  administrator. The tray icon creates *User* codes only.
- **Admins.** The last admin can never be removed, and an admin cannot remove their own account
  from Telegram.
- **Private chats only.** The bot accepts only private chats in which the chat ID equals the
  sender's ID. If it is added to a group or channel, it leaves at once.

---

## Tray icon

The tray icon (`predator-tray.exe`) starts for every user who signs in, with one instance per
session. Only the configured **owner** Windows account can use it: the account that ran the
setup, or another account set with `set-owner-sid`. For any other account, the icon quietly
exits. The icon is grey while the service is not running. The tooltip shows the service state,
the Telegram connection and a Tailscale line, such as
`Tailscale: service running · Connected · 100.64.0.5`.

| Menu item | What it does |
|---|---|
| **Open Dashboard** | Opens your bot (`https://t.me/YourPcBot`) in the browser. Greyed out until the bot name is known. |
| **Service Status** | A window with the service state, version, uptime, Telegram connection, monitors, memory and a live Tailscale status |
| **Pair Telegram User…** | Creates a 10-minute pairing code for a *User* account and shows the code and link. A notification appears when the account has paired, or when the code expired or was invalidated. |
| **Telegram Users…** | Lists the paired accounts. To remove one, use `/users` in Telegram or the management menu. |
| **Disable/Enable Login Monitoring, SSH Monitoring, Notifications, Power Management, Tailscale** | Quick switches, each labelled with what a click does. A check mark shows that the feature is on. *Notifications* is the *Login Notifications* feature. |
| **Feature Settings ▸** | All nine features, with check marks |
| **Start Service (admin)…** | Only shown while the service is not running. Starts it after a UAC prompt. |
| **Restart Service** | Restarts the service. Greyed out unless it is running. |
| **Exit Tray Application** | Closes the tray icon only. The service keeps running. |

Pairing, the user list and the feature switches need a running service that answers. While the
service is stopped, those items are greyed out.

---

## Command-line reference

`PredatorRemoteController.exe` and the installed `C:\Program Files\Predator\predator-service.exe`
are the same program. Started without arguments, it opens the setup or the management menu.
Started with a command, it works as a management tool. The commands marked *Administrator* need
an elevated PowerShell and say so when they do not have it. Run `help` for the full usage text.

| Command | What it does |
|---|---|
| `setup [--token-file F] [--telegram-id ID] [--yes]` | The setup wizard or management menu, started from a prompt. `--yes` never asks a question: a new installation then needs `--token-file` and `--telegram-id`, and an existing one is updated to this version and gets the given token and user. |
| `pair [--admin] [--ttl SECS]` | *Administrator.* Creates a one-time 8-digit pairing code (valid 60 to 3600 seconds, 600 by default) and waits until it is used. `--admin` makes the new account an Admin. |
| `users [list \| remove ID]` | Lists the paired Telegram accounts, or removes one at once (*Administrator*) |
| `set-owner --telegram-id ID` | *Administrator.* Replaces **all** paired accounts with this one, as Admin |
| `install [--start]` | *Administrator.* Registers or updates the service from the folder of this file. It also protects the data folder, turns on logon auditing and registers the tray autostart. The folder must be one that only administrators can change. |
| `uninstall [--keep-audit-policy] [--purge-data]` | *Administrator.* Stops and removes the service and the tray autostart, and puts back the original audit policy unless you add `--keep-audit-policy`. `--purge-data` also deletes the data folder. Unlike the menu's Uninstall, this command leaves the program files in place. |
| `start` / `stop` | *Administrator.* Starts or stops the service |
| `status` | Shows the service state and, while it runs, version, uptime, Telegram connection, HTTPS transport, monitors, queue, memory, Tailscale and features |
| `set-token [--file PATH \| --stdin] [--no-verify]` | *Administrator.* Stores the bot token, encrypted with DPAPI. Without options it asks for the token with hidden input. The token is checked with Telegram unless you add `--no-verify`. A running service uses the new token after a restart. |
| `set-owner-sid (--user NAME \| --sid SID)` | *Administrator.* Sets the Windows account that may use the tray icon |
| `features [list \| enable KEY \| disable KEY]` | Lists the feature switches, or changes one (*Administrator*). Keys are listed in [Features screen](#features-screen). |
| `audit (status \| enable \| restore)` | *Administrator.* Shows the logon audit policy, turns on what login alerts need, or puts back the policy saved at installation |
| `selftest [--tailscale]` | A health report that changes nothing: configuration, permissions, event-log access and Telegram reachability. `--tailscale` also queries Tailscale. Run it elevated so it can check the protected data folder. |
| `console [--token-file F] [--stdin-commands] [--dry-run]` | Runs the service in the foreground for testing. It **always** simulates power, lock, logout and Tailscale Up/Down. See [docs/BUILDING.md](docs/BUILDING.md#console-mode). |
| `version` / `help` | Prints the version, or the usage text |

Options that work with every command:

| Option | Effect |
|---|---|
| `--data-dir DIR` | Uses `DIR` instead of `%ProgramData%\Predator`. Meant for `console` and tests; `setup`, `install`, `uninstall`, `start` and `stop` refuse it. |
| `--verbose`, `-v` | Prints debug output |

---

## Settings

Settings live in `%ProgramData%\Predator\settings.json`. Most of them are managed for you by
pairing, the feature switches and `set-token`. To change an option by hand, edit the file in an
editor started as administrator, then restart the service: run `predator-service.exe stop` and
then `start`, or use **Restart Service** in the tray menu.

| Key | Default | Meaning |
|---|---|---|
| `features` | see [Features screen](#features-screen) | On/off state of the nine features. Easier to change with `/features`, the tray icon or `features enable/disable`. |
| `stale_command_secs` | `300` | Commands that change something and are older than this many seconds are ignored |
| `confirm_timeout_secs` | `60` | How long a shutdown, restart, sleep or hibernate confirmation stays valid |
| `lifecycle_notifications` | `true` | Send the PREDATOR ONLINE, GOING OFFLINE and RESUMED notices |
| `auto_clean_chat` | `true` | Delete short-lived chat messages automatically. With `false`, nothing is deleted and `/clear` only says that cleaning is off. |
| `chat_clean_after_secs` | `600` | Seconds without use before a short-lived message is deleted. Values are limited to 60 seconds … 47 hours. |
| `dry_run` | `false` | Only simulate power, lock, logout and Tailscale Up/Down. Read when the service starts. An empty file named `DRY_RUN` in the data folder does the same. |
| `authorized_users` | `[]` | The paired accounts (`id`, `name`, `role`, `added_unix`). Manage them by pairing and removing accounts. |
| `owner_windows_sid` | set by the setup | The Windows account that may use the tray icon (`set-owner-sid`) |
| `bot_username` | from Telegram | The bot's username, used for links |

A complete file looks like this:

```json
{
  "version": 1,
  "authorized_users": [
    { "id": 123456789, "name": "alex", "role": "admin", "added_unix": 1795766400 }
  ],
  "owner_windows_sid": "S-1-5-21-…-1001",
  "bot_username": "YourPcBot",
  "features": {
    "battery_info": true,
    "failed_login_notifications": false,
    "login_monitoring": true,
    "login_notifications": true,
    "logout_notifications": true,
    "network_info": true,
    "power_management": true,
    "ssh_monitoring": true,
    "tailscale_management": true
  },
  "dry_run": false,
  "stale_command_secs": 300,
  "confirm_timeout_secs": 60,
  "lifecycle_notifications": true,
  "auto_clean_chat": true,
  "chat_clean_after_secs": 600
}
```

The bot token is never stored in this file.

**Advanced: HTTPS transport.** Predator normally talks to Telegram over its own direct HTTPS
connection, and uses WinHTTP only when a machine-wide proxy is configured or turns out to be
needed. The environment variable `PREDATOR_HTTP_TRANSPORT` (`direct`, `winhttp` or `auto`) forces
the choice. See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Files and locations

| Path | Content |
|---|---|
| `C:\Program Files\Predator\predator-service.exe` | The installed program: service, management menu and command-line tool |
| `C:\Program Files\Predator\predator-tray.exe` | The tray icon |
| `%ProgramData%\Predator\` | The data folder. Only SYSTEM and Administrators can open it. |
| `…\settings.json` | Settings and paired accounts (see [Settings](#settings)) |
| `…\token.dat` | The bot token, encrypted with DPAPI |
| `…\queue.json` | Alerts waiting to be delivered |
| `…\history.json` | The last 50 login events |
| `…\telegram-state.json` | The last Telegram update that was handled, and the bot it belongs to |
| `…\chat-cleanup.json` | IDs and times of the messages that auto-clean will delete (no message text) |
| `…\audit-backup.json` | The audit policy from before the installation, put back on uninstall |
| `…\bookmarks\security.xml`, `openssh.xml`, `openssh-admin.xml` | Read positions in the event logs, so events that happen while the service is stopped are still reported |
| `…\logs\predator.log` | Operational log: at most 1 MiB plus one older copy. Tokens are removed from it. |
| `…\logs\security.log` | Security log: unauthorized attempts, pairing, removals, power, lock, logout and Tailscale requests, feature changes. At most 1 MiB plus three older copies. |
| `…\DRY_RUN` | Optional, empty file: turns on simulation mode |
| Service `PredatorRemoteController` | The Windows service (automatic start, LocalSystem) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` → `PredatorTray` | Starts the tray icon at sign-in |
| `\\.\pipe\PredatorRemoteController` | The local connection between the tray icon and the service |

---

## Resource usage

The program is designed to stay out of the way. These figures are the measured idle footprint on
a Windows 11 x64 PC: 10 minutes at idle, both login monitors active, Telegram online.

| Measure | `predator-service.exe` | `predator-tray.exe` |
|---|---|---|
| Private memory | ≈ 2.4 MB | ≈ 1.7 MB |
| Working set | ≈ 3.3 MB on average | — |
| Wake-ups (context switches) | ≈ 5 per minute | ≈ 5.7 per minute |
| CPU cycles in 10 minutes | ≈ 18.5 million | ≈ 8 million |
| CPU | effectively 0 %: under one 15.6 ms timer tick of CPU time in 10 minutes | effectively 0 % |
| Threads | 7–10 | 1–4 |
| Handles | ≈ 245 | — |
| File size | `PredatorRemoteController.exe` ≈ 2.6 MB, including the tray | ≈ 0.5 MB |

The numbers on your PC depend on the hardware, the Windows build and the other software.
`scripts\measure.ps1` measures the installed service and tray icon on your own PC: CPU, memory,
threads and handles (see [docs/BUILDING.md](docs/BUILDING.md#measuring-the-footprint)).

How it stays this small:

- **Event-driven, no polling loops.** Every thread waits in the kernel: on the Telegram long poll,
  on event-log signals, on an event or on the local pipe. Apart from the long poll, no periodic
  timer runs more often than once a minute.
- **Event-log subscriptions with bookmarks.** Windows signals new Security and OpenSSH events, and
  Predator reads only the logs that were signalled. Saved bookmarks let it pick up where it
  stopped after a restart.
- **One long poll over Windows' own TLS.** A single 50-second `getUpdates` long poll runs over a
  direct TCP connection with Windows SChannel (TLS 1.2/1.3) and HTTP/1.1 keep-alive. There is no
  HTTP thread pool; WinHTTP is only a fallback for proxies and is not even loaded otherwise.
- **Work on demand.** Network, battery and Tailscale information is read only when you ask for it.
  The Wi-Fi name is looked up in a short-lived helper process, so COM and WinRT never load into the
  service. The Tailscale status is read with `--peers=false`, so the reply stays small however big
  your tailnet is.
- **Delay-loaded DLLs.** Libraries that are needed only for occasional work load the first time
  they are used.
- **Small binaries.** `opt-level = "z"`, fat LTO, one codegen unit, stripped symbols and the C
  runtime linked in statically, so no Visual C++ Redistributable is needed. The tray copy inside
  the release file is never loaded into memory unless the setup extracts it.
- **Memory given back after bursts.** The service trims its working set once after start-up and
  after bursts of on-demand work, never on a timer. It also runs with EcoQoS, so Windows may run
  its short bursts on efficient cores.
- **Limited state.** The queue holds at most 1000 alerts, the history 50 events and the
  auto-clean list 500 messages; log files are capped at 1 MiB.
- **A quiet tray icon.** Windows notifies the tray icon when the service starts or stops, so it
  does not poll. A safety refresh runs every 5 minutes, and the input-method machinery is switched
  off.

---

## Security

Predator runs as **LocalSystem** and can shut down the PC, so it is built defensively:

- **Who can give commands.** Only Telegram accounts paired with a code created on the PC itself,
  recognised by their numeric user ID, never by username, and only in private chats.
- **Strangers.** They get `⛔ Access denied. This bot is private.`, and every paired account gets
  an alert.
- **No remote shell.** Every action is a fixed function. Telegram input is never passed to a shell
  or a command line. The only programs the service ever starts are Tailscale's own command-line
  tool and app with fixed arguments, and its own helper modes.
- **The bot token** is encrypted with DPAPI in a folder that only SYSTEM and Administrators can
  open, and it is never written to a log.
- **The connection to Telegram** uses TLS 1.2/1.3 through Windows SChannel, with full certificate
  and host-name checks. Predator listens on no network port.
- **The local connection with the tray icon** is a named pipe. Every request is checked against
  the caller's Windows account (SID), and the tray icon makes sure it is talking to the real
  service.
- **Safety rules.** Dangerous actions need a one-time confirmation that expires, and late commands
  are not carried out.

Details and how to report a vulnerability: [SECURITY.md](SECURITY.md). Keep your bot token
private. If it leaks, revoke it in @BotFather (`/revoke`) and enter the new token with
**4 Change bot token** in the management menu.

---

## Building from source

You need Windows 10/11 x64, [Rust](https://rustup.rs) (stable, MSVC toolchain, 1.88 or newer) and
Visual Studio Build Tools with the *Desktop development with C++* workload.

```powershell
git clone https://github.com/4fnanK/Predator-Remote-Controller.git
cd Predator-Remote-Controller
.\scripts\build.ps1
```

`build.ps1` checks the formatting, builds, runs the tests and clippy, and writes
`dist\PredatorRemoteController.exe` and `dist\SHA256SUMS.txt`. The full guide is in
[docs/BUILDING.md](docs/BUILDING.md). It covers the two-stage build that puts the tray inside the
release file, console mode for testing without touching the PC, the test and measurement scripts,
and how releases are made.

---

## Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). It covers a service that does not start,
an invalid token, missing login or SSH alerts, Tailscale problems, proxies, a hidden tray icon,
leftovers after an uninstall and safe testing in dry-run mode. A good first step is
`predator-service.exe status` and `predator-service.exe selftest`, run from an elevated
PowerShell.

## Architecture

How the service, the Telegram dispatcher, the login monitors, the offline queue and the tray icon
fit together is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Contributing

Bug reports, ideas and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
first. Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 4fnanK
