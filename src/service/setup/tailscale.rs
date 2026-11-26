//! The Tailscale check at the end of setup: why it matters and what to do (pure text from a
//! [`TailscaleStatus`], unit-tested). Setup only reads the status; it never runs `up` or `down`.

use crate::sys::{ServiceState, TailscaleStatus};

/// Why setup looks at Tailscale at all.
pub(crate) const WHY: &str = "\
Why Tailscale? Vigil controls this PC through Telegram, but Telegram cannot give you its
desktop or a shell. Tailscale puts the PC on your own private network (tailnet), so Remote
Desktop (RDP) and SSH reach it from anywhere - no port forwarding on the router, nothing
exposed to the internet. That is why /tailscale up is the first thing to send when you need
real remote access: once it is up, connect with RDP or SSH to the PC's Tailscale address.";

/// "Run unattended" advice: without it Tailscale only connects while a user is signed in.
pub(crate) const UNATTENDED: &str = "\
Recommended: in the Tailscale app choose Preferences -> Run unattended. Then Tailscale (and
/tailscale up from Telegram) works even when nobody is signed in to Windows, for example
after a reboot or a power cut.";

/// One-line state for the summary.
pub(crate) fn summary(st: &TailscaleStatus) -> String {
    if !st.installed {
        return "not installed".into();
    }
    if st.service != ServiceState::Running {
        return format!("installed, service {}", st.service.label().to_lowercase());
    }
    if st.connected {
        return match &st.ipv4 {
            Some(ip) => format!("connected ({ip})"),
            None => "connected".into(),
        };
    }
    match st.backend_state.as_deref() {
        Some(state) => format!("installed, not connected ({state})"),
        None => "installed, not connected".into(),
    }
}

/// What to tell the user about this PC's Tailscale state.
pub(crate) fn advice(st: &TailscaleStatus) -> Vec<String> {
    let mut v = Vec::new();
    if !st.installed {
        v.push(
            "Tailscale is not installed. Install it from https://tailscale.com/download/windows, sign in once,".into(),
        );
        v.push("then come back to this menu (Status) or just use /tailscale in Telegram.".into());
        v.push(UNATTENDED.into());
        return v;
    }
    match &st.service {
        ServiceState::Running => {}
        ServiceState::NotInstalled => {
            v.push("The Tailscale program was found, but its Windows service is missing. Reinstall Tailscale.".into());
            return v;
        }
        other => v.push(format!(
            "The Tailscale service is {}. It starts automatically with Windows; /tailscale up starts it too.",
            other.label().to_lowercase()
        )),
    }
    if st.connected {
        let ip = st.ipv4.as_deref().unwrap_or("its 100.x.y.z address");
        let host = st.hostname.as_deref().map(|h| format!(" as {h}")).unwrap_or_default();
        v.push(format!("Tailscale is connected{host}. RDP or SSH to {ip} works from your other devices."));
    } else {
        match st.backend_state.as_deref() {
            Some("NeedsLogin") => v.push("Tailscale is not logged in: open the Tailscale app and log in once.".into()),
            Some("NeedsMachineAuth") => v.push("This device waits for approval in the Tailscale admin console.".into()),
            Some("Stopped") => v.push("Tailscale is turned off; /tailscale up in Telegram connects it.".into()),
            _ if st.service == ServiceState::Running => {
                v.push("Tailscale is not connected right now; /tailscale up in Telegram connects it.".into())
            }
            _ => {}
        }
    }
    v.push(UNATTENDED.into());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> TailscaleStatus {
        TailscaleStatus { installed: true, service: ServiceState::Running, ..Default::default() }
    }

    #[test]
    fn not_installed() {
        let s = TailscaleStatus::default();
        assert_eq!(summary(&s), "not installed");
        let a = advice(&s).join("\n");
        assert!(a.contains("tailscale.com/download") && a.contains("Run unattended"), "{a}");
    }

    #[test]
    fn connected_and_not() {
        let mut s = st();
        s.connected = true;
        s.ipv4 = Some("100.64.0.5".into());
        s.hostname = Some("my-pc".into());
        assert_eq!(summary(&s), "connected (100.64.0.5)");
        let a = advice(&s).join("\n");
        assert!(a.contains("RDP or SSH to 100.64.0.5") && a.contains("as my-pc"), "{a}");
        assert!(a.contains("Run unattended"));

        let mut s = st();
        s.backend_state = Some("NeedsLogin".into());
        assert_eq!(summary(&s), "installed, not connected (NeedsLogin)");
        assert!(advice(&s).join("\n").contains("log in once"));

        let mut s = st();
        s.service = ServiceState::Stopped;
        assert!(summary(&s).starts_with("installed, service"));
        assert!(advice(&s).join("\n").contains("/tailscale up starts it"));

        let mut s = st();
        s.service = ServiceState::NotInstalled;
        assert!(advice(&s).join("\n").contains("Reinstall Tailscale"));
    }

    #[test]
    fn explanation_names_rdp_and_ssh() {
        assert!(WHY.contains("RDP") && WHY.contains("SSH") && WHY.contains("/tailscale up"));
    }
}
