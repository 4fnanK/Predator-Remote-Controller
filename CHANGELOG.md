# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-27

First public release.

### Added

- **Single-file release.** `PredatorRemoteController.exe` contains the Windows service, the setup,
  the management menu, the command-line tool and the tray icon.
- **Guided setup.** It runs after a double-click and a UAC prompt:
  - the bot token is entered hidden, checked with Telegram and stored encrypted with DPAPI;
  - the first Telegram account is paired as Admin;
  - the program files are installed, SHA-256 verified;
  - the service, the logon audit policy and the tray autostart are set up;
  - Tailscale is checked.
- **Unattended installation** with `setup --token-file F --telegram-id ID --yes`.
- **Management menu** when the program is started again: status, pairing, users, change token,
  update (with automatic rollback), open the bot, uninstall.
- **Login alerts** from the Windows Security log (4624, 4625, 4634, 4647, 4778, 4779, 1102) and the
  OpenSSH logs: Windows sign-ins, unlocks, Remote Desktop connects and disconnects, sign-outs,
  failed sign-ins, SSH logins, failed SSH logins, closed SSH sessions and a cleared Security log.
  Failed-login alerts are rate-limited, with a summary of the suppressed ones.
- **Telegram control panel** with commands and inline buttons:
  - status, network, battery and login history;
  - feature switches;
  - lock and logout, which run at once;
  - shutdown, restart, sleep and hibernate behind a one-time confirmation that expires.
- **Tailscale management.** Up starts the Tailscale service and app and connects; Down
  disconnects, closes the app and stops the service. This makes Remote Desktop and SSH reachable
  over the tailnet on demand.
- **Several Telegram accounts.** Up to 20, with the roles Admin and User. Accounts are added with
  one-time 8-digit pairing codes from the tray, the menu or `pair`, by sending `/pair CODE` or
  opening a deep link. Admins can remove accounts with `/users`, and the other users are told about
  every change.
- **Offline queue.** Alerts are kept on disk and delivered late with their original time. Commands
  and button presses that arrive late are not carried out.
- **Chat auto-clean.** Menus, replies and status notices are deleted automatically, and `/clear`
  deletes them at once. Login and security alerts stay.
- **Tray icon** with status, quick feature toggles, pairing, the user list and service start and
  restart.
- **Small idle footprint.** About 2.4 MB of private memory and about 5 wake-ups per minute, through:
  event-driven threads, event-log subscriptions with bookmarks, a direct HTTPS client on Windows
  SChannel, delay-loaded DLLs, a statically linked C runtime and EcoQoS.
- **Build and release tooling.** `scripts/build.ps1`, `scripts/test.ps1` and `scripts/measure.ps1`,
  CI on GitHub Actions, and tag-triggered releases with SHA-256 checksums.

[1.0.0]: https://github.com/4fnanK/Predator-Remote-Controller/releases/tag/v1.0.0
