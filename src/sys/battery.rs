//! Battery status via GetSystemPowerStatus (only queried on demand — no monitoring).
//!

use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};

use super::{AcStatus, BatteryInfo};
use crate::util::win::WinError;

// SYSTEM_POWER_STATUS constants (windows-sys does not define them).
const AC_OFFLINE: u8 = 0;
const AC_ONLINE: u8 = 1;
const FLAG_HIGH: u8 = 1;
const FLAG_CHARGING: u8 = 8;
const FLAG_NO_BATTERY: u8 = 128;
const FLAG_UNKNOWN: u8 = 255;
const PERCENT_UNKNOWN_MIN: u8 = 101;
const SAVER_ON: u8 = 1;

/// Read the current battery/AC state. Desktops without a battery return `present: false`.
pub fn battery_info() -> Result<BatteryInfo, String> {
    let mut s = SYSTEM_POWER_STATUS::default();
    // SAFETY: `s` is a valid out-parameter.
    if unsafe { GetSystemPowerStatus(&mut s) } == 0 {
        return Err(WinError::last("Could not read the power status (GetSystemPowerStatus)").to_string());
    }
    Ok(interpret(s.ACLineStatus, s.BatteryFlag, s.BatteryLifePercent, s.SystemStatusFlag, s.BatteryLifeTime))
}

/// Pure interpretation of SYSTEM_POWER_STATUS fields (unit-testable).
pub fn interpret(
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
) -> BatteryInfo {
    let ac = match ac_line_status {
        AC_ONLINE => AcStatus::Connected,
        AC_OFFLINE => AcStatus::Disconnected,
        _ => AcStatus::Unknown,
    };
    let battery_saver = system_status_flag == SAVER_ON;
    let unknown = battery_flag == FLAG_UNKNOWN;
    let no_battery = !unknown && battery_flag & FLAG_NO_BATTERY != 0;
    if no_battery {
        return BatteryInfo {
            present: false,
            percent: None,
            charging: false,
            full: false,
            ac,
            seconds_left: None,
            battery_saver,
        };
    }
    let percent = (battery_life_percent < PERCENT_UNKNOWN_MIN).then_some(battery_life_percent);
    let charging = !unknown && battery_flag & FLAG_CHARGING != 0;
    let on_ac = ac == AcStatus::Connected;
    // On AC and not charging: full when Windows says 100 % or reports the "high" level without charging
    // (vendor charge limits keep the battery just below 100 % but it is still "fully charged").
    let full = on_ac && !charging && (percent == Some(100) || (!unknown && battery_flag & FLAG_HIGH != 0));
    let seconds_left = (battery_life_time != u32::MAX && !on_ac && !charging).then_some(battery_life_time);
    BatteryInfo { present: true, percent, charging, full, ac, seconds_left, battery_saver }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNKNOWN_TIME: u32 = u32::MAX;

    #[test]
    fn desktop_without_battery() {
        let b = interpret(1, 128, 255, 0, UNKNOWN_TIME);
        assert_eq!(
            b,
            BatteryInfo {
                present: false,
                percent: None,
                charging: false,
                full: false,
                ac: AcStatus::Connected,
                seconds_left: None,
                battery_saver: false,
            }
        );
    }

    #[test]
    fn charging_on_ac() {
        // Low (2) + charging (8) at 30 %.
        let b = interpret(1, 2 | 8, 30, 0, UNKNOWN_TIME);
        assert!(b.present && b.charging && !b.full);
        assert_eq!(b.percent, Some(30));
        assert_eq!(b.ac, AcStatus::Connected);
        assert_eq!(b.seconds_left, None);
        // High + charging at 85 %.
        let b = interpret(1, 1 | 8, 85, 0, UNKNOWN_TIME);
        assert!(b.charging && !b.full);
    }

    #[test]
    fn discharging_on_battery() {
        let b = interpret(0, 1, 85, 0, 7_800);
        assert!(b.present && !b.charging && !b.full);
        assert_eq!(b.percent, Some(85));
        assert_eq!(b.ac, AcStatus::Disconnected);
        assert_eq!(b.seconds_left, Some(7_800));
        // Remaining time not yet estimated.
        let b = interpret(0, 0, 50, 1, UNKNOWN_TIME);
        assert_eq!(b.seconds_left, None);
        assert!(b.battery_saver);
    }

    #[test]
    fn full_on_ac() {
        // Measured on this laptop: AC=1, BatteryFlag=1, 100 %, lifetimes -1.
        let b = interpret(1, 1, 100, 0, UNKNOWN_TIME);
        assert!(b.present && b.full && !b.charging);
        assert_eq!(b.percent, Some(100));
        assert_eq!(b.seconds_left, None);
        // Charge limit at 80 %: on AC, high, not charging → full.
        let b = interpret(1, 1, 80, 0, UNKNOWN_TIME);
        assert!(b.full);
        // On AC, medium level (flag 0), not charging, 60 % → not full.
        let b = interpret(1, 0, 60, 0, UNKNOWN_TIME);
        assert!(!b.full && !b.charging);
    }

    #[test]
    fn unknown_status() {
        let b = interpret(255, 255, 255, 0, UNKNOWN_TIME);
        assert!(b.present);
        assert_eq!(b.percent, None);
        assert!(!b.charging && !b.full);
        assert_eq!(b.ac, AcStatus::Unknown);
        assert_eq!(b.seconds_left, None);
        // Unknown flags never set the charging bit, but a valid 100 % on AC is still full.
        let b = interpret(1, 255, 100, 0, UNKNOWN_TIME);
        assert!(!b.charging && b.full);
    }

    #[test]
    fn live_battery_info() {
        let b = battery_info().expect("GetSystemPowerStatus");
        println!("battery_info() = {b:?}");
        if let Some(p) = b.percent {
            assert!(p <= 100);
        }
    }
}
