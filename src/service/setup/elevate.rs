//! Administrator rights for setup: relaunch this program elevated (UAC prompt, `runas`), wait
//! for it and pass its exit code on; and whether the console window belongs to this process only
//! (then the window closes when we exit, so the last screen needs a "Press Enter").

use std::path::{Path, PathBuf};
use std::ptr::null;

use windows_sys::Win32::Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx};
use windows_sys::Win32::System::Console::GetConsoleProcessList;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use super::SetupOptions;
use crate::util::win::{OwnedHandle, WinError, last_error, wide, wide_path};

/// Quote one argument so that `CommandLineToArgvW` (and Rust's argument parser) gives it back
/// unchanged: backslashes are literal except before a quote.
pub(crate) fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Arguments joined into one parameter string.
pub(crate) fn join_args(args: &[String]) -> String {
    args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

/// Arguments for the elevated copy: `setup --invoking-sid <SID>` plus the options the user gave
/// (relative paths made absolute: the elevated process may start in another directory).
pub(crate) fn elevated_args(opts: &SetupOptions, invoking_sid: Option<&str>, cwd: &Path) -> Vec<String> {
    let mut args = vec!["setup".to_string()];
    if let Some(sid) = invoking_sid {
        args.push("--invoking-sid".into());
        args.push(sid.to_string());
    }
    if let Some(f) = &opts.token_file {
        let abs: PathBuf = if f.is_absolute() { f.clone() } else { cwd.join(f) };
        args.push("--token-file".into());
        args.push(abs.display().to_string());
    }
    if let Some(id) = opts.telegram_id {
        args.push("--telegram-id".into());
        args.push(id.to_string());
    }
    if opts.yes {
        args.push("--yes".into());
    }
    if opts.verbose {
        args.push("--verbose".into());
    }
    args
}

/// Outcome of [`relaunch_elevated`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Relaunch {
    /// The elevated copy ran and exited with this code.
    Exited(u32),
    /// The user declined the UAC prompt.
    Declined,
}

/// Start this executable elevated with `args` (UAC prompt), wait until it exits and return its
/// exit code. It gets its own console window.
pub(crate) fn relaunch_elevated(args: &[String]) -> Result<Relaunch, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Cannot find this program's path: {e}"))?;
    let cwd = std::env::current_dir().ok();
    let verb = wide("runas");
    let file = wide_path(&exe);
    let params = wide(&join_args(args));
    let dir = cwd.as_deref().map(wide_path);
    // ShellExecuteEx may hand the request to shell extensions, which want COM. Failure (already
    // initialised in another mode) does not matter for starting an .exe.
    // SAFETY: plain COM initialisation of this thread; never uninitialised (process exits soon).
    unsafe { CoInitializeEx(null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: params.as_ptr(),
        lpDirectory: dir.as_ref().map_or(null(), |d| d.as_ptr()),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised; every string it points to outlives the call.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let code = last_error();
        if code == ERROR_CANCELLED {
            return Ok(Relaunch::Declined);
        }
        return Err(format!("Cannot start setup as administrator: {}", WinError::new(code, "ShellExecuteExW")));
    }
    if info.hProcess.is_null() {
        // Should not happen for an .exe; nothing to wait for.
        return Ok(Relaunch::Exited(0));
    }
    let process = OwnedHandle(info.hProcess);
    // SAFETY: valid process handle (SEE_MASK_NOCLOSEPROCESS), closed by OwnedHandle.
    if unsafe { WaitForSingleObject(process.raw(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(format!("Waiting for the setup window failed: {}", WinError::last("WaitForSingleObject")));
    }
    let mut code = 0u32;
    // SAFETY: valid process handle; `code` is a valid out pointer.
    if unsafe { GetExitCodeProcess(process.raw(), &mut code) } == 0 {
        return Err(format!("Cannot read the exit code of setup: {}", WinError::last("GetExitCodeProcess")));
    }
    Ok(Relaunch::Exited(code))
}

/// True when no other process (cmd.exe, PowerShell, Windows Terminal's shell) shares our console:
/// the window was opened for us (double-click, elevated relaunch) and closes when we exit.
pub(crate) fn console_is_ours() -> bool {
    let mut pids = [0u32; 4];
    // SAFETY: `pids` holds 4 entries; the call writes at most that many.
    let n = unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) };
    n == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Split like CommandLineToArgvW does for arguments after the program name.
    fn split(cmd: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut have = false;
        let chars: Vec<char> = cmd.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let start = i;
                while i < chars.len() && chars[i] == '\\' {
                    i += 1;
                }
                let n = i - start;
                if i < chars.len() && chars[i] == '"' {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        cur.push('"');
                        i += 1;
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                have = true;
                continue;
            }
            if c == '"' {
                in_quotes = !in_quotes;
                have = true;
            } else if (c == ' ' || c == '\t') && !in_quotes {
                if have {
                    args.push(std::mem::take(&mut cur));
                    have = false;
                }
            } else {
                cur.push(c);
                have = true;
            }
            i += 1;
        }
        if have {
            args.push(cur);
        }
        args
    }

    #[test]
    fn quoting_round_trips() {
        let cases = [
            "setup",
            "",
            r"C:\Program Files\Predator\token.txt",
            r"C:\dir with space\",
            r"C:\trailing\\",
            r#"say "hi""#,
            r#"a\"b"#,
            r"\\server\share\x y",
            "tab\there",
        ];
        for c in cases {
            let joined = join_args(&[c.to_string(), "next".to_string()]);
            assert_eq!(split(&joined), vec![c.to_string(), "next".to_string()], "{c:?} -> {joined}");
        }
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg("two words"), "\"two words\"");
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn elevated_arguments() {
        let opts = SetupOptions {
            token_file: Some(PathBuf::from("tok.txt")),
            telegram_id: Some(123456789),
            yes: true,
            invoking_sid: None,
            verbose: true,
        };
        let a = elevated_args(&opts, Some("S-1-5-21-1-2-3-1001"), Path::new(r"D:\work dir"));
        assert_eq!(
            a,
            vec![
                "setup",
                "--invoking-sid",
                "S-1-5-21-1-2-3-1001",
                "--token-file",
                r"D:\work dir\tok.txt",
                "--telegram-id",
                "123456789",
                "--yes",
                "--verbose"
            ]
        );
        let a = elevated_args(&SetupOptions::default(), None, Path::new(r"C:\"));
        assert_eq!(a, vec!["setup"]);
        let abs = SetupOptions { token_file: Some(PathBuf::from(r"E:\t.txt")), ..Default::default() };
        assert!(elevated_args(&abs, None, Path::new(r"C:\x")).contains(&r"E:\t.txt".to_string()));
    }
}
