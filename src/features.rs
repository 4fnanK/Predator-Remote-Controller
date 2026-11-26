//! The nine individually switchable features.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Feature {
    LoginMonitoring,
    SshMonitoring,
    LoginNotifications,
    FailedLoginNotifications,
    LogoutNotifications,
    PowerManagement,
    NetworkInfo,
    BatteryInfo,
    TailscaleManagement,
}

impl Feature {
    /// Display order (also the index used in Telegram callback data).
    pub const ALL: [Feature; 9] = [
        Feature::LoginMonitoring,
        Feature::SshMonitoring,
        Feature::LoginNotifications,
        Feature::FailedLoginNotifications,
        Feature::LogoutNotifications,
        Feature::PowerManagement,
        Feature::NetworkInfo,
        Feature::BatteryInfo,
        Feature::TailscaleManagement,
    ];

    /// Stable machine key (settings file, IPC).
    pub fn key(self) -> &'static str {
        match self {
            Feature::LoginMonitoring => "login_monitoring",
            Feature::SshMonitoring => "ssh_monitoring",
            Feature::LoginNotifications => "login_notifications",
            Feature::FailedLoginNotifications => "failed_login_notifications",
            Feature::LogoutNotifications => "logout_notifications",
            Feature::PowerManagement => "power_management",
            Feature::NetworkInfo => "network_info",
            Feature::BatteryInfo => "battery_info",
            Feature::TailscaleManagement => "tailscale_management",
        }
    }

    /// Human label.
    pub fn label(self) -> &'static str {
        match self {
            Feature::LoginMonitoring => "Windows Login Monitoring",
            Feature::SshMonitoring => "SSH Monitoring",
            Feature::LoginNotifications => "Login Notifications",
            Feature::FailedLoginNotifications => "Failed Login Notifications",
            Feature::LogoutNotifications => "Logout Notifications",
            Feature::PowerManagement => "Power Management",
            Feature::NetworkInfo => "Network Information",
            Feature::BatteryInfo => "Battery Information",
            Feature::TailscaleManagement => "Tailscale Management",
        }
    }

    /// Short label used on compact buttons.
    pub fn short_label(self) -> &'static str {
        match self {
            Feature::LoginMonitoring => "Login Monitor",
            Feature::SshMonitoring => "SSH Monitor",
            Feature::LoginNotifications => "Login Alerts",
            Feature::FailedLoginNotifications => "Failed Logins",
            Feature::LogoutNotifications => "Logout Alerts",
            Feature::PowerManagement => "Power",
            Feature::NetworkInfo => "Network",
            Feature::BatteryInfo => "Battery",
            Feature::TailscaleManagement => "Tailscale",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|f| *f == self).unwrap_or(0)
    }

    pub fn from_index(i: usize) -> Option<Feature> {
        Self::ALL.get(i).copied()
    }

    pub fn from_key(k: &str) -> Option<Feature> {
        let k = k.trim().to_ascii_lowercase().replace(['-', ' '], "_");
        Self::ALL.iter().copied().find(|f| f.key() == k)
    }

    /// Factory default. Failed-login alerts start disabled (they can be noisy); everything else on.
    pub fn default_enabled(self) -> bool {
        !matches!(self, Feature::FailedLoginNotifications)
    }
}

/// Persisted on/off state for every feature. Unknown keys in the file are ignored, missing keys
/// take their default, so the format is forward/backward compatible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureSet {
    enabled: [bool; 9],
}

impl Default for FeatureSet {
    fn default() -> Self {
        let mut enabled = [true; 9];
        for f in Feature::ALL {
            enabled[f.index()] = f.default_enabled();
        }
        Self { enabled }
    }
}

impl FeatureSet {
    pub fn is_enabled(&self, f: Feature) -> bool {
        self.enabled[f.index()]
    }

    /// Set a feature; returns true if the value changed.
    pub fn set(&mut self, f: Feature, on: bool) -> bool {
        let changed = self.enabled[f.index()] != on;
        self.enabled[f.index()] = on;
        changed
    }

    /// Flip a feature; returns the new value.
    pub fn toggle(&mut self, f: Feature) -> bool {
        let v = !self.enabled[f.index()];
        self.enabled[f.index()] = v;
        v
    }

    pub fn iter(&self) -> impl Iterator<Item = (Feature, bool)> + '_ {
        Feature::ALL.iter().map(move |f| (*f, self.is_enabled(*f)))
    }
}

impl Serialize for FeatureSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let m: BTreeMap<&str, bool> = self.iter().map(|(f, on)| (f.key(), on)).collect();
        m.serialize(s)
    }
}

impl<'de> Deserialize<'de> for FeatureSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let m: BTreeMap<String, bool> = BTreeMap::deserialize(d)?;
        let mut fs = FeatureSet::default();
        for (k, v) in m {
            if let Some(f) = Feature::from_key(&k) {
                fs.set(f, v);
            }
        }
        Ok(fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_roundtrip() {
        for (i, f) in Feature::ALL.iter().enumerate() {
            assert_eq!(f.index(), i);
            assert_eq!(Feature::from_index(i), Some(*f));
            assert_eq!(Feature::from_key(f.key()), Some(*f));
        }
        assert_eq!(Feature::from_key("Power-Management"), Some(Feature::PowerManagement));
        assert_eq!(Feature::from_key("nope"), None);
    }

    #[test]
    fn defaults_and_toggle() {
        let mut fs = FeatureSet::default();
        assert!(fs.is_enabled(Feature::LoginMonitoring));
        assert!(!fs.is_enabled(Feature::FailedLoginNotifications));
        assert!(fs.toggle(Feature::FailedLoginNotifications));
        assert!(fs.is_enabled(Feature::FailedLoginNotifications));
        assert!(!fs.set(Feature::FailedLoginNotifications, true));
        assert!(fs.set(Feature::FailedLoginNotifications, false));
    }

    #[test]
    fn serde_tolerant() {
        let fs: FeatureSet = serde_json::from_str(r#"{"ssh_monitoring":false,"unknown":true}"#).unwrap();
        assert!(!fs.is_enabled(Feature::SshMonitoring));
        assert!(fs.is_enabled(Feature::BatteryInfo));
        let s = serde_json::to_string(&fs).unwrap();
        let back: FeatureSet = serde_json::from_str(&s).unwrap();
        assert_eq!(back, fs);
    }
}
