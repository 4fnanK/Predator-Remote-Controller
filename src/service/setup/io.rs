//! Console input/output of the setup wizard and the management menu, behind a small trait so the
//! dialogs can be tested with scripted input.

use std::io::{BufRead, Write};

use super::super::winsec::{self, Secret};

/// Text in, text out. `None` from [`Io::ask`] means end of input (closed console or pipe).
pub(crate) trait Io {
    /// Print one line (or several, separated by `\n`).
    fn say(&mut self, text: &str);
    /// Show `prompt` (no newline) and read one line, without the line break.
    fn ask(&mut self, prompt: &str) -> Option<String>;
    /// Like [`Io::ask`], but the input is not echoed (bot token).
    fn ask_secret(&mut self, prompt: &str) -> Result<Secret, String>;
}

/// The process console (stdout / stdin).
pub(crate) struct ConsoleIo;

impl Io for ConsoleIo {
    fn say(&mut self, text: &str) {
        println!("{text}");
    }

    fn ask(&mut self, prompt: &str) -> Option<String> {
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
        }
    }

    fn ask_secret(&mut self, prompt: &str) -> Result<Secret, String> {
        let _ = std::io::stdout().flush();
        winsec::read_hidden_line(prompt)
    }
}

/// `y`/`yes`/`n`/`no` (any case, surrounding spaces ignored); an empty answer is `default`.
/// `None` = not a yes/no answer.
pub(crate) fn parse_yes_no(answer: &str, default: bool) -> Option<bool> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "" => Some(default),
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

/// Ask a yes/no question (`[Y/n]` or `[y/N]` shows the default). Repeats on other answers (at
/// most 5 times). `None` = end of input or no usable answer: callers treat that as "cancel".
pub(crate) fn ask_yes_no(io: &mut dyn Io, question: &str, default: bool) -> Option<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    for _ in 0..5 {
        let answer = io.ask(&format!("{question} {hint} "))?;
        if let Some(v) = parse_yes_no(&answer, default) {
            return Some(v);
        }
        io.say("  Please answer y (yes) or n (no).");
    }
    None
}

/// "Press Enter to close" (end of input is fine too).
pub(crate) fn pause(io: &mut dyn Io) {
    let _ = io.ask("\nPress Enter to close this window.");
}

/// Scripted console for tests: answers come from a list, everything printed is recorded.
#[cfg(test)]
pub(crate) struct ScriptedIo {
    pub answers: std::collections::VecDeque<String>,
    pub out: Vec<String>,
}

#[cfg(test)]
impl ScriptedIo {
    pub fn new(answers: &[&str]) -> Self {
        Self { answers: answers.iter().map(|s| s.to_string()).collect(), out: Vec::new() }
    }

    /// Everything printed so far (prompts included), one string.
    pub fn text(&self) -> String {
        self.out.join("\n")
    }
}

#[cfg(test)]
impl Io for ScriptedIo {
    fn say(&mut self, text: &str) {
        self.out.push(text.to_string());
    }

    fn ask(&mut self, prompt: &str) -> Option<String> {
        self.out.push(prompt.to_string());
        self.answers.pop_front()
    }

    fn ask_secret(&mut self, prompt: &str) -> Result<Secret, String> {
        self.out.push(prompt.to_string());
        // A secret is never echoed into the transcript.
        Ok(Secret::new(self.answers.pop_front().unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_no_parsing() {
        assert_eq!(parse_yes_no("", true), Some(true));
        assert_eq!(parse_yes_no("  ", false), Some(false));
        assert_eq!(parse_yes_no("Y", false), Some(true));
        assert_eq!(parse_yes_no(" yes ", false), Some(true));
        assert_eq!(parse_yes_no("No", true), Some(false));
        assert_eq!(parse_yes_no("n", true), Some(false));
        assert_eq!(parse_yes_no("maybe", true), None);
        assert_eq!(parse_yes_no("1", true), None);
    }

    #[test]
    fn ask_repeats_until_a_valid_answer() {
        let mut io = ScriptedIo::new(&["what", "y"]);
        assert_eq!(ask_yes_no(&mut io, "Continue?", false), Some(true));
        assert!(io.text().contains("Continue? [y/N]"));
        assert!(io.text().contains("Please answer y"));
        let mut io = ScriptedIo::new(&[""]);
        assert_eq!(ask_yes_no(&mut io, "Q?", true), Some(true));
        let mut io = ScriptedIo::new(&[]);
        assert_eq!(ask_yes_no(&mut io, "Q?", true), None, "end of input cancels");
        let mut io = ScriptedIo::new(&["a", "b", "c", "d", "e", "y"]);
        assert_eq!(ask_yes_no(&mut io, "Q?", true), None, "gives up after 5 unusable answers");
    }

    #[test]
    fn secrets_are_not_recorded() {
        let mut io = ScriptedIo::new(&["123:secret"]);
        let s = io.ask_secret("Token: ").unwrap();
        assert_eq!(s.expose(), "123:secret");
        assert!(!io.text().contains("secret"));
    }
}
