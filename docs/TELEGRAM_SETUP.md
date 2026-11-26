# Telegram setup

This guide creates a private bot for Vigil, keeps its token safe and links
your Telegram account (and, if you like, the accounts of other people) to the PC. Allow about 5
minutes.

Every PC needs **its own bot**: two installations that share a token disturb each other
(`409 Conflict`, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#409-conflict)).

## 1. Create the bot with @BotFather

1. In Telegram, open **[@BotFather](https://t.me/BotFather)**. It is the official bot for creating
   bots and has a blue verification check mark.
2. Send `/newbot`.
3. Enter a **display name**, for example `Vigil PC`. You can change it later.
4. Enter a **username**. It must end in `bot` (for example `YourPcBot`), and it must not be taken
   already.
5. BotFather replies with the **bot token**, which looks like this:

   ```
   123456789:AAH...35 characters...
   ```

   Copy it. Setup asks for it in the next step. You can show it again at any time in @BotFather
   with `/mybots` → your bot → *API Token*.

## 2. Optional BotFather settings

Send these commands to @BotFather and pick your bot when asked:

| Command | Choose | Why |
|---|---|---|
| `/setjoingroups` | **Disable** | Nobody can add the bot to a group. If it is added anyway, it leaves immediately. |
| `/setprivacy` | **Enable** (the default) | In groups, the bot would see only commands addressed to it. Vigil works only in private chats. |
| `/setdescription` | optional | For example: *Private remote control for my PC.* |
| `/setuserpic` | optional | You can use `assets/predator-256.png` from the repository. |

You do **not** need `/setcommands`. The service registers its command list (`/menu`, `/status`,
`/network`, ...) by itself whenever it loads the token.

## 3. Keep the token secret

Anyone who has the token can act as your bot. They could read the messages sent to it, or poll it
in parallel with the service, which causes `409 Conflict` errors and lost commands. They still
cannot control your PC, because Vigil only obeys the numeric user ids of the accounts paired
on the PC. Even so, treat the token like a password:

- Do not paste it into chats, screenshots, issue reports or scripts kept in Git.
- If you use a token file for an [unattended setup](#unattended-setup), **delete the file**
  afterwards.
- Vigil never prints the token. Its logs automatically redact anything that looks like a token.

### Rotating the token

Do this when the token may have leaked, or as routine hygiene:

1. In @BotFather send `/revoke`, pick the bot, and copy the **new** token. The old token stops
   working at once.
2. On the PC, run `Vigil.exe` (or
   `C:\Program Files\Predator\predator-service.exe` without arguments), confirm the UAC prompt and
   choose **4 Change bot token**. Paste the new token into the hidden prompt; it is checked with
   Telegram before it is stored. Answer **Yes** to *Restart the service now so it uses the new
   token?*

The same from an elevated PowerShell:

```powershell
$exe = "C:\Program Files\Predator\predator-service.exe"
& $exe set-token      # hidden prompt; paste the new token
& $exe stop
& $exe start
```

`set-token --file <path>` reads the token from a file instead (delete the file afterwards), and
`set-token --stdin` from standard input. `set-token` checks the token with Telegram first
(`--no-verify` skips that check) and records the bot's `@username`.

Paired accounts stay authorized. The running service keeps using the previous token until it
restarts. A service holding a revoked token reports `invalid token` (401) and checks the stored
token again every 30 minutes, so the restart only makes the change take effect immediately.

### Switching to a different bot

You can also store the token of a **different** bot with **4 Change bot token** (or `set-token`)
and restart the service. The service notices that the bot changed (it compares the bot id reported
by Telegram with the one saved in `telegram-state.json`), discards the old bot's polling position
and starts from the new bot's pending messages. The paired accounts stay the same, but **every
person must open the chat with the new bot and press Start** once before it can message them. The
chat auto-clean list of the old bot is forgotten (nothing is deleted in either chat), so leftover
menus in the old bot's chat stay until you delete them yourself.

## 4. How setup asks for the token

Double-click `Vigil.exe` and confirm the UAC prompt. The setup wizard explains
what it installs and asks *Install now?*. Its first step is the token:

```
[1/6] Telegram bot token
------------------------
You need your own Telegram bot (free, takes a minute). If you do not have one yet:
  1. In Telegram, open a chat with @BotFather (the official bot with the blue check mark).
  2. Send /newbot, choose a display name, then a username that ends in "bot".
  3. BotFather answers with a token that looks like 123456789:AAH...  Copy it.
Paste the token below. It is not shown while you type and is stored encrypted (DPAPI).
Keep it secret: anyone who has it can read and send messages as your bot.

Bot token (hidden; press Enter alone to cancel):
  Checking the token with Telegram...
  OK - this is the token of @YourPcBot (Vigil PC).
```

- The input is **hidden**. Spaces and line breaks that come with a pasted token are removed.
- The token is first checked for the right format, then with Telegram (`getMe`). A wrong token is
  asked for again, up to 5 times. Press Enter alone to cancel the setup.
- When a token is already stored on this PC (for example after an uninstall that kept the data
  folder), setup asks *A bot token for @YourPcBot is already stored on this PC. Keep using it?*

How the token is stored:

- It is encrypted with **Windows DPAPI** in machine scope and written to
  `%ProgramData%\Predator\token.dat`. Setup creates that folder itself, owned by Administrators,
  with access only for SYSTEM and Administrators. A folder that another account prepared is moved
  aside, and its `token.dat` is never used.
- Any process on this PC that can *read* `token.dat` could decrypt it, so the file's permissions
  are the real protection. Copying `token.dat` to another PC gives nothing usable.
- The token never appears on a command line, in the console history or in a log. It is never
  stored in `settings.json` and never in plain text. Only the bot's `@username` is kept in
  `settings.json` (for the links in the tray and the menu).

## 5. Pair your Telegram account

Vigil obeys only Telegram accounts that were **paired on the PC**, identified by their numeric
user id. Usernames are never trusted. Up to 20 accounts can be paired.

Pairing uses a **one-time 8-digit code** that is shown only on the PC. It is never sent to
Telegram and never logged.

### The first account (during setup)

Step 3 of the wizard (*Link your Telegram account*) shows a code:

```
Pairing code:  1234 5678
Valid for:     10 min (until 14:35), single use
Role:          Admin

On the phone with the Telegram account to add:
  - open this link and press Start:   https://t.me/YourPcBot?start=pair-12345678
  - or send this message to @YourPcBot:   /pair 12345678

Waiting for the new account… (Ctrl+C aborts)
```

1. On your phone, open the link and press **Start**, or open a **private chat** with your bot and
   send `/pair 1234 5678` (spaces and dashes in the code are fine).
2. The bot answers `✅ Paired with DESKTOP-01. Send /menu to start.` and the setup window shows
   `Paired: @alex (Telegram user id 123456789) as Admin.`
3. Setup continues with the program files, the service, the tray icon and the Tailscale check.

The first account always becomes an **Admin**. If the code expires or pairing fails, setup asks
*Try again?*; you can also continue without a paired account and pair later from the menu.

### Further accounts

Create a new code on the PC in one of three ways:

| Where | How | Role |
|---|---|---|
| Tray icon | Right-click → **Pair Telegram User…**. A dialog shows the code and the link | User (Admin if nobody is paired yet) |
| Setup menu | Run `Vigil.exe` → **2 Pair a Telegram user**. It asks *Make this account an Admin (can also remove users)?* | User or Admin |
| Command line | `& "C:\Program Files\Predator\predator-service.exe" pair [--admin] [--ttl SECS]` | User, or Admin with `--admin` |

The new person then opens the link or sends `/pair CODE` to the bot, exactly as above. Every other
paired account is told (*👤 NEW TELEGRAM USER PAIRED*). The tray and the console show the result.

Rules:

- A code works **once** and expires after **10 minutes** (`--ttl` accepts 60 … 3600 seconds).
- Only **one** code is active at a time: a new code replaces the previous one. Closing the console
  (or Ctrl+C) and a service restart cancel it.
- After **5 wrong attempts** in total the code is invalidated. Each Telegram account may also make
  only 5 wrong guesses per hour.
- A failed attempt is never explained to the sender: the bot answers it like any message from a
  stranger. Check the result on the PC (see
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md#pairing-code-does-not-work)).
- Admin codes need an elevated prompt (the setup menu always is). A User code can also be created
  from the tray owner's normal prompt while the service runs.
- **Keep the code private**: whoever sends it first gets access to the PC.

### Roles and the user list

- **User**: every command and button (status, power, Tailscale, features ...).
- **Admin**: the same, and can remove other accounts.

`/users` in Telegram lists every account (`👑` Admin, `👤` User) with its id and the date it was
added. Admins get a `🗑 Remove <name>` button for every other account; removal takes effect at once
and the remaining accounts are told (*TELEGRAM USER REMOVED*). The last admin cannot be removed,
and admins cannot remove their own account in Telegram.

On the PC, menu **3 Telegram users (list / remove)** does the same, as do
`predator-service.exe users list` and `users remove ID` (elevated).
`set-owner --telegram-id ID` replaces **all** accounts by that one (as Admin), for example to lock
everyone else out at once.

### Unattended setup

For a scripted install you can skip the interactive pairing and authorize your account by its
numeric id. You need the id **only** for this.

**Find your numeric Telegram user id.** Telegram does not show it in its own settings. Open a chat
with a user-info bot (search Telegram for "userinfo"; these are third-party bots that only echo
your account details) and send it any message. It replies with your **Id**, a number such as
`123456789`. If your account is already paired with another PC, `predator-service.exe users list`
on that PC shows it too.

**Run the setup.** Save the token in a text file (for example with Notepad, as `token.txt`), then
in an elevated PowerShell in the folder with the download:

```powershell
.\Vigil.exe setup --token-file .\token.txt --telegram-id 123456789 --yes
Remove-Item .\token.txt
```

- `--yes` never asks anything. A new installation then needs both `--token-file` and
  `--telegram-id`; the account becomes an Admin.
- On a PC where Vigil is installed already, the same command updates the program when the file
  is a different version, stores the given token, authorizes the given id as Admin, and prints the
  status.
- Started from a normal prompt it asks for elevation (UAC) and continues in a new window that
  closes at the end; start it elevated to read the output.
- Telegram does not let a bot start a conversation. An account added by id must **open the bot
  and press Start** once before it can receive alerts.

## 6. Test it

1. Send **`/menu`** to your bot. The main menu appears, with the computer name, uptime and monitor
   state.
2. Tap **📊 System Status** and **🌐 Network** to check that the buttons respond.
3. Lock the PC and unlock it, or sign out and back in, to receive your first login alert.
4. Optional: from an account that is **not** paired, send `/start` to the bot. That account gets
   `⛔ Access denied. This bot is private.`, and every paired account receives an
   **🚨 UNAUTHORIZED ACCESS ATTEMPT** alert.
5. Optional: test a power confirmation **safely** in dry-run mode first. See
   [TROUBLESHOOTING.md](TROUBLESHOOTING.md#dry-run-mode-safe-testing).
6. Send `/status`, then `/network`. Once the network reply arrives, your `/status` command and its
   reply disappear from the chat; that is the chat auto-clean (next section).

## 7. Keeping the chat clean

Vigil deletes its short-lived messages by itself, so the chat ends up holding only the alerts
worth keeping.

- **Kept:** Windows logins, logouts and failed logins (including the *failed login attempts
  suppressed* summary), SSH logins, failed SSH logins and closed SSH sessions, and security alerts
  such as *UNAUTHORIZED ACCESS ATTEMPT*, *NEW TELEGRAM USER PAIRED* and *TELEGRAM USER REMOVED*.
- **Deleted automatically:** menus, status screens, command results, power confirmations once they
  can no longer be confirmed, status notices (`VIGIL ONLINE`, `VIGIL GOING OFFLINE`,
  `VIGIL RESUMED`, `FEATURE CHANGED`, audit and monitor-gap notices) and the commands you type.
  They go when you send your next message, or after 10 minutes without use. Pressing a button on
  a menu keeps that menu alive for another 10 minutes.
- **`/clear`** deletes all of them at once, including the `/clear` message, and cancels a pending
  power confirmation. It sends no reply.

Things to know:
- Telegram does not let bots delete messages older than **48 hours**. Anything older stays.
- The `/pair` message and the `✅ Paired with …` reply of the **first** pairing during setup are
  exchanged by the setup window, not by the service, so they are not deleted automatically. Delete
  them by hand. Later pairings are cleaned like any other command.
- Messages sent while auto-clean was switched off are not known to Vigil. Remove them once with
  Telegram's **Clear history** in the bot chat. That also removes old login alerts, so read them
  first if you want to keep any.
- The switch and the time are `auto_clean_chat` (default `true`) and `chat_clean_after_secs`
  (default `600`, allowed 60 seconds to 47 hours) in `%ProgramData%\Predator\settings.json`. Edit
  the file in an elevated editor and restart the service. With `auto_clean_chat` set to `false`,
  nothing is deleted and `/clear` only says that cleaning is off.

More detail: [TROUBLESHOOTING → Old bot messages are not deleted](TROUBLESHOOTING.md#old-bot-messages-are-not-deleted).

## Privacy notes

- The bot serves only **paired accounts in their own private chat** with it (checked by numeric
  user id; the chat must be the sender's own). It **leaves every group and channel** it is added
  to, and button presses anywhere else are refused (`⛔ Not authorized`). Edited messages are never
  executed.
- Anyone else who writes to the bot gets `⛔ Access denied. This bot is private.` at most once an
  hour, and every paired account receives an **UNAUTHORIZED ACCESS ATTEMPT** alert with that
  account's numeric id, username, name and the first characters of its message (a pairing code in
  it is hidden).
- Every paired account receives every alert and can use every command, including power actions.
  Pair only people you would trust with the PC itself.
- Bot chats are not end-to-end encrypted. Alerts and command replies pass through Telegram's
  servers. Vigil sends only what you see in the messages: computer name, user names, logon
  method, source IP, network and battery summaries, and Tailscale status (address, hostname,
  tailnet). It never collects passwords, Wi-Fi BSSIDs, browsing data or file contents.
- On the PC, `settings.json` keeps the numeric id, display name (`@username` or first name), role
  and date added of every paired account. For the chat auto-clean Vigil stores only message ids
  and times (`chat-cleanup.json`), never message text. Pairing codes exist only in memory.
