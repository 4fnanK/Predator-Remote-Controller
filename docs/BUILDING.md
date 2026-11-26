# Building Predator Remote Controller

This guide covers building the program from source, running it safely while you develop, the test
and measurement scripts, and how releases are published. To simply use the program, download the
ready-made file from the
[latest release](https://github.com/4fnanK/Predator-Remote-Controller/releases/latest) instead
(see the [README](../README.md#quick-start)).

## Requirements

- **Windows 10 or 11, x64.** The program uses the Win32 API directly and builds only for Windows.
- **Rust through [rustup](https://rustup.rs),** the stable toolchain for the MSVC host
  (`stable-x86_64-pc-windows-msvc`), version **1.88 or newer**. The crate uses edition 2024 and
  declares `rust-version = "1.88"`.
  - The components `rustfmt` and `clippy` are needed by `scripts\build.ps1`.
  - The target `x86_64-pc-windows-msvc` is the default on an MSVC host.
- **Visual Studio Build Tools** (or Visual Studio) with the **Desktop development with C++**
  workload, which provides the MSVC compiler and linker and the **Windows SDK**. The Rust MSVC
  toolchain uses this linker.
- **Git**, to clone the repository.
- **PowerShell 5.1 or newer** for the scripts in `scripts\`.

A typical setup on a fresh PC:

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Rustlang.Rustup
rustup default stable-x86_64-pc-windows-msvc
rustup component add rustfmt clippy
```

No other tools are needed. `build.rs` writes the icons, version information and application
manifest into the executables itself, so `rc.exe` is not required. The C runtime is linked
statically through `.cargo/config.toml` (`+crt-static`), so the executables do not need the
Visual C++ Redistributable.

## Get the source

```powershell
git clone https://github.com/4fnanK/Predator-Remote-Controller.git
cd Predator-Remote-Controller
```

## Build the release with `scripts\build.ps1`

```powershell
.\scripts\build.ps1
# or, when script execution is restricted:
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

The script runs these steps in order and stops at the first failure:

| Step | Command |
|---|---|
| 1. Formatting | `cargo fmt --all -- --check` |
| 2. Type check | `cargo check --all-targets` |
| 3. Tests | `cargo test --all-targets` |
| 4. Lints | `cargo clippy --all-targets -- -D warnings` |
| 5. Tray | `cargo build --release --target x86_64-pc-windows-msvc --bin predator-tray` |
| 6. Service with the tray inside | `cargo build --release --target x86_64-pc-windows-msvc --bin predator-service --features embed-tray`, with `PREDATOR_EMBED_TRAY` set to the tray from step 5 |

It then writes the release folder, `dist\` by default:

| File | Content |
|---|---|
| `PredatorRemoteController.exe` | The whole program in one file: service, setup and management menu, command-line tool and the embedded tray |
| `SHA256SUMS.txt` | The SHA-256 of every file in the folder, one `<hash> *<file>` line each |
| `README.md`, `LICENSE` | Copied from the repository |

Finally it checks the result:

- `PredatorRemoteController.exe version` must print the version from `Cargo.toml`;
- `help` must work;
- the tray extracted from the exe must be byte-for-byte the same as the tray built in step 5.

The script installs nothing and never touches a service. The exit code is 0 on success and the
failing cargo exit code (or 1) otherwise. If an error has a likely fix, the script prints a hint,
such as `cargo fmt --all` or `rustup component add clippy`.

### Parameters

| Parameter | Meaning |
|---|---|
| `-OutDir <folder>` | Release folder instead of `<repo>\dist`. It must be a dedicated folder: not a drive root, not the repository root, not a junction or symbolic link. The default `dist\` is recreated on every run. A different folder must be empty, or contain only the four release files. |
| `-SkipChecks` | Only run the two release builds (steps 5 and 6) and skip formatting, check, tests and clippy. Meant for quick local iterations. |

The script also respects `CARGO_TARGET_DIR`, and it adds `%USERPROFILE%\.cargo\bin` to `PATH` when
cargo is installed there but not on the path.

## The two-stage build: putting the tray inside the service

The release is a single file, but the program has two executables:

- `predator-service.exe`: the service, setup, management menu and command-line tool;
- `predator-tray.exe`: the tray icon, which runs in each user's session.

To ship them as one file, the tray is built first and then embedded into the service:

1. `predator-tray.exe` is built normally, **without** the `embed-tray` feature.
2. `predator-service.exe` is built with the Cargo feature **`embed-tray`**. The environment
   variable **`PREDATOR_EMBED_TRAY`** must hold the *full path* of the tray from stage 1.
   - `build.rs` checks that the file is a Windows executable and computes its SHA-256 (passed on
     as `PREDATOR_EMBED_TRAY_SHA256`).
   - `src/service/setup/embedded.rs` includes the bytes with `include_bytes!`.
3. During setup and updates, the program checks the embedded tray against that hash before it
   writes `C:\Program Files\Predator\predator-tray.exe`. A damaged download is refused.

The embedded bytes live in the read-only data section of the executable. They are never loaded
into memory unless setup extracts them, so the running service does not pay for them.

Use the `embed-tray` feature only with `--bin predator-service`, and build the tray without it.
Without `PREDATOR_EMBED_TRAY`, a build with the feature fails with a clear message.

## Building the binaries with cargo

The release build by hand, exactly as `build.ps1` does it:

```powershell
cargo build --release --target x86_64-pc-windows-msvc --bin predator-tray
$env:PREDATOR_EMBED_TRAY = (Resolve-Path .\target\x86_64-pc-windows-msvc\release\predator-tray.exe).Path
cargo build --release --target x86_64-pc-windows-msvc --bin predator-service --features embed-tray
Remove-Item Env:PREDATOR_EMBED_TRAY
```

Without the embedded tray, for example during development:

```powershell
cargo build --release --target x86_64-pc-windows-msvc    # both binaries
cargo build                                              # debug build, in target\debug
```

A `predator-service.exe` built without `embed-tray` still works. When it installs itself, it takes
the tray from the `predator-tray.exe` next to it. If that file is missing, setup stops with an
explanation.

Two related notes:

- **Installing a development build.** `predator-service.exe install` refuses to register the
  service from a folder that other accounts can change, such as `target\`, because a LocalSystem
  service must not run from there. Start the built exe without arguments instead: setup copies it
  to `C:\Program Files\Predator` and protects the folder.
- **Icons.** The icon files `assets\predator.ico` and `assets\predator-off.ico` are created with
  `cargo run --example icongen`.

## Console mode

The `console` command runs the complete service in the foreground, in a terminal. Console mode
**always simulates** shutdown, restart, sleep, hibernate, lock, logout and Tailscale Up/Down; the
`--dry-run` flag is accepted only for clarity. Use a separate data folder so the installed service
and its settings are never touched:

```powershell
cargo run --bin predator-service -- console --data-dir .\data
```

How it behaves:

- **Without a bot token,** Telegram is disabled: the login monitors run and alerts are queued in
  `.\data\queue.json`.
- **Reading the Windows Security log needs an elevated prompt.** Without elevation, the login
  monitor reports an access error, and everything else still works.
- **Stopping.** Ctrl+C stops the console. So does the end of the input, or a line that is just
  `quit` or `exit`.
- **The installed service.** While it is running, the console refuses to use the default data
  folder.

To try the bot end to end, use a **separate test bot**. Two programs polling the same bot token
get `409 Conflict` from Telegram, so never reuse the token of an installed copy that is running.

```powershell
New-Item -ItemType Directory -Force .\data | Out-Null
Set-Content .\data\token.txt '123456789:AAH...'        # token of your test bot
cargo run --bin predator-service -- set-owner --telegram-id 123456789 --data-dir .\data
cargo run --bin predator-service -- console --data-dir .\data --token-file .\data\token.txt --stdin-commands
```

- `--token-file` reads a plain-text token. Instead, you can store an encrypted token in the folder
  with `set-token --data-dir .\data`; `console --data-dir .\data` then uses it.
- `set-owner --telegram-id` authorizes your Telegram account in `.\data\settings.json`. With
  `--data-dir`, these commands need no elevation.
- With `--stdin-commands`, each line you type goes to the bot as a message from the first paired
  account, such as `/status` or `/tailscale up`. A line starting with `cb:` is a button press, such
  as `cb:nav:feat`, which opens the features screen. The replies appear in that account's Telegram
  chat with the test bot.
- `.\data\`, `token.txt` and `settings.json` are listed in `.gitignore`, so a test token is not
  committed by accident.

## Tests

```powershell
cargo test --all-targets
```

This runs the unit and integration tests of the library, both binaries and the `icongen` example.
The tests use mocks and temporary folders. They **never** shut down, restart, sleep, hibernate,
lock or log off the PC, never change Tailscale, and never touch an installed copy of the service.

Some tests are marked `#[ignore]` because they probe the real PC: event-log access, network,
battery and Tailscale status, and HTTPS connections to api.telegram.org, badssl.com and httpbin.org
without a bot token, which needs internet access. Run them with:

```powershell
cargo test --all-targets -- --include-ignored
```

They do not change the PC's state, but two of them write test entries:

- one writes a test event (source `PredatorSpinTest`) to the Application event log;
- one makes failed SSH logins for the non-existent user `predator-spin-test` against the local
  `sshd`. If the service is installed, it reports these as failed SSH logins.

### `scripts\test.ps1`

```powershell
.\scripts\test.ps1               # cargo test --all-targets, then the installed service's selftest
.\scripts\test.ps1 -Ignored      # also run the #[ignore] live tests (-- --include-ignored)
.\scripts\test.ps1 -NoSelftest   # skip the selftest
```

After the tests, when the Predator service is installed, the script runs its
`predator-service.exe selftest`, which changes nothing. Run the script from an elevated PowerShell
so the selftest can read the protected data folder. It prints a summary table and exits with 0
when everything passed and 1 otherwise.

## Measuring the footprint

`scripts\measure.ps1` samples the **installed** service, found through the Service Control
Manager, and every running `predator-tray.exe`. It only reads process counters and never changes
anything:

```powershell
.\scripts\measure.ps1                                    # 300 s, one sample every 5 s
.\scripts\measure.ps1 -Seconds 600 -IntervalSeconds 5 -OutFile .\measure.md
```

| Parameter | Default | Meaning |
|---|---|---|
| `-Seconds` | `300` | How long to measure (10 … 86400) |
| `-IntervalSeconds` | `5` | Sampling interval (1 … 3600) |
| `-OutFile` | — | Also write the Markdown result to this file |

The result is a Markdown table with these values for each process:

- the average CPU % over the run and the highest CPU % of any single interval;
- private bytes and working set (minimum, average and maximum);
- thread and handle counts.

It needs no administrator rights: when the CPU time of the LocalSystem service cannot be read
directly, it uses `Win32_Process` instead. Leave the PC idle while measuring to get the idle
footprint. The exit code is 1 if the service is not running.

## Continuous integration

`.github/workflows/ci.yml` runs `scripts\build.ps1` on `windows-latest` for every push to `main`,
for every pull request and on manual start. It uploads `PredatorRemoteController.exe` and
`SHA256SUMS.txt` as a build artifact named `PredatorRemoteController-<commit>`.

## Making a release

Releases are built and published by `.github/workflows/release.yml`:

1. Set the new version in `Cargo.toml` (`version = "X.Y.Z"`) and add an entry to `CHANGELOG.md`.
   Commit both.
2. Create a tag that matches the version exactly, with a leading `v`, and push it:

   ```powershell
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

3. The workflow then runs on `windows-latest`:
   - it runs `scripts\build.ps1` (all checks, tests and both builds);
   - it checks that `PredatorRemoteController.exe version` matches the tag, and fails if, for
     example, the tag is `v1.2.0` but `Cargo.toml` says `1.1.0`;
   - it publishes the GitHub Release `Predator Remote Controller vX.Y.Z` with the assets
     `PredatorRemoteController.exe` and `SHA256SUMS.txt`. The release text comes from
     `.github/RELEASE_NOTES.md`.

To rebuild and publish an existing tag again, start the **Release** workflow by hand and enter the
tag, for example `v1.0.0`.
