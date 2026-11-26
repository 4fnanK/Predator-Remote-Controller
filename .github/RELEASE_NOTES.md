Monitor and control your Windows PC from a private Telegram bot: instant login alerts, status,
lock, power actions with a confirmation, and Tailscale up and down for Remote Desktop and SSH from
anywhere. What changed in this version is listed in
[CHANGELOG.md](https://github.com/4fnanK/Vigil/blob/main/CHANGELOG.md).

## Download

| File | What it is |
|---|---|
| `Vigil.exe` | The whole program in one file: service, setup, management menu and tray icon. Windows 10/11 x64. |
| `SHA256SUMS.txt` | SHA-256 checksums for checking the download |

## Check the download

In PowerShell, in the folder with both files:

```powershell
Get-FileHash .\Vigil.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The hash must equal the one on the `Vigil.exe` line of `SHA256SUMS.txt`
(upper or lower case does not matter).

> **Windows SmartScreen:** the program is not code-signed, so Windows may show *"Windows protected
> your PC"*. Once you have checked the hash, click **More info → Run anyway**.

## Quick start

1. **Create a bot.** In Telegram, open [@BotFather](https://t.me/BotFather), send `/newbot` and
   copy the token it gives you.
2. **Start the setup.** Double-click `Vigil.exe` and confirm the UAC prompt.
3. **Paste the token** when the setup asks for it. It is hidden while you type and stored
   encrypted.
4. **Pair your account.** On your phone, open the link the setup shows and tap **Start**, or send
   `/pair CODE` to your bot. Your account becomes the first Admin.
5. **Done.** Send `/menu` to your bot. Optional but recommended: install
   [Tailscale](https://tailscale.com/download/windows) and turn on *Run unattended*, so that
   **🛡 Tailscale → ▶️ Up** makes the PC reachable for Remote Desktop and SSH from anywhere.

## Upgrading

Download the new `Vigil.exe`, start it and confirm the UAC prompt. In the
management menu, choose **5 Update installed program to this version**. Your bot token, Telegram
users and settings are kept. If the service was running and the new version does not start, the
previous version is restored automatically.

## Documentation

- [README](https://github.com/4fnanK/Vigil#readme): features, every bot
  command and button, pairing, settings and the command-line reference
- [Troubleshooting](https://github.com/4fnanK/Vigil/blob/main/docs/TROUBLESHOOTING.md)
- [Security policy](https://github.com/4fnanK/Vigil/blob/main/SECURITY.md)
