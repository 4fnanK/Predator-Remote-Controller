# Contributing

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Building

Requirements: Windows 10/11 x64, [Rust](https://rustup.rs) (stable, MSVC toolchain, 1.88 or newer) and
Visual Studio Build Tools with the "Desktop development with C++" workload (MSVC + Windows SDK).

```powershell
git clone https://github.com/4fnanK/Vigil.git
cd Vigil
.\scripts\build.ps1          # fmt check, check, tests, clippy, release build → dist\Vigil.exe
```

For quick iterations: `cargo check --all-targets`, `cargo test --lib`, and run the service in the
foreground with `cargo run --bin predator-service -- console --data-dir .\data` (console mode always
simulates shutdown/restart/sleep/hibernate/lock/logout and Tailscale up/down).

## Rules for changes

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test --all-targets` must pass (CI runs `scripts\build.ps1`).
- Keep the footprint small: no new background threads, timers or polling loops on idle paths, no
  async runtime, no large dependencies. Measure with `scripts\measure.ps1` when in doubt.
- Never panic across FFI; wrap Win32 callbacks in `catch_unwind`; close every handle.
- Never log the bot token, pairing codes or message contents of other users.
- Tests must **never** shut down, restart, sleep, hibernate, lock or log off the machine, change
  Tailscale's state or touch an installed copy of the service. Use mocks or console dry-run mode.
- Only shutdown, restart, sleep and hibernate may ask for confirmation in the bot. Every other
  action executes immediately — please keep it that way.
- Telegram input must never reach a shell or a process command line.

## Pull requests

1. Fork, create a branch, make focused commits.
2. Describe what changed and how you tested it (include `measure.ps1` numbers for performance work).
3. Make sure CI is green.
