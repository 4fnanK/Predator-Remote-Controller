# Security policy

Predator Remote Controller runs as **LocalSystem** and can shut down, lock or log off the PC it is
installed on. Security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository (GitHub Security Advisories).

Include:
- the version (`PredatorRemoteController.exe version`),
- what an attacker needs (local account? network access? a Telegram account?),
- steps to reproduce and the impact you observed.

You will get an answer as soon as possible. Fixes are released as a new version and credited in
the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Security model (short)

| Area | Protection |
|---|---|
| Who can control the PC | Only Telegram accounts paired with a one-time code created **on the PC itself** (admin rights or the tray owner). Authorization uses the numeric Telegram user id only — never usernames. Private chats only; the bot leaves groups. |
| Pairing codes | 8 random digits, single use, 10-minute lifetime, invalidated after 5 wrong attempts, per-user attempt limits. Unauthorized users get the same generic reply whether or not a code exists. |
| Dangerous actions | Shutdown, restart, sleep and hibernate need a per-user confirmation button that expires and can be used once. Commands sent while the PC was offline are not executed late. |
| Bot token | Stored encrypted with Windows DPAPI in `%ProgramData%\Predator` (SYSTEM + Administrators only). Never logged; log lines are redacted. |
| No remote shell | Telegram input is never passed to a shell. Every action is a fixed function; the only programs ever started are Tailscale's own CLI with fixed arguments and the program's own helper modes. |
| Network | TLS 1.2/1.3 through Windows SChannel with full certificate-chain and host-name validation. |
| Local IPC (tray) | Named pipe restricted to SYSTEM, Administrators and the interactive user; every request is authorized by the caller's Windows account; the client verifies the pipe server is the real service. |

Keep your bot token private. If it leaks, revoke it in @BotFather (`/revoke`) and run the program
again to enter the new token.
