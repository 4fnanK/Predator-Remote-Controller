//! Time helpers: Unix timestamps, ISO-8601 parsing (event log `SystemTime`), local-time formatting
//! through the Windows time-zone database (no chrono dependency).

use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_SECS: i64 = 11_644_473_600;

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Current Unix time in milliseconds.
pub fn now_unix_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse an ISO-8601 UTC timestamp such as `2026-11-25T06:35:15.1884769Z` (fractional seconds
/// optional, trailing `Z` optional) into Unix seconds.
pub fn parse_iso8601_utc(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse::<i64>().ok() };
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3_600 + mi * 60 + se)
}

/// Convert a Windows FILETIME value (100-ns intervals since 1601) to Unix seconds.
pub fn filetime_to_unix(ft: u64) -> i64 {
    (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS
}

/// Convert Unix seconds to a FILETIME value.
pub fn unix_to_filetime(unix: i64) -> u64 {
    ((unix + EPOCH_DIFF_SECS).max(0) as u64) * 10_000_000
}

/// Broken-down local time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
}

/// Convert Unix seconds to local time using the system time-zone rules (incl. DST).
pub fn to_local(unix: i64) -> LocalTime {
    let ft_val = unix_to_filetime(unix);
    let ft = FILETIME { dwLowDateTime: ft_val as u32, dwHighDateTime: (ft_val >> 32) as u32 };
    unsafe {
        let mut utc: SYSTEMTIME = std::mem::zeroed();
        let mut local: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&ft, &mut utc) == 0 {
            return LocalTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
        }
        if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
            local = utc;
        }
        LocalTime {
            year: local.wYear,
            month: local.wMonth,
            day: local.wDay,
            hour: local.wHour,
            minute: local.wMinute,
            second: local.wSecond,
        }
    }
}

/// `14:30:25` (local time).
pub fn fmt_time(unix: i64) -> String {
    let t = to_local(unix);
    format!("{:02}:{:02}:{:02}", t.hour, t.minute, t.second)
}

/// `25 Nov 2026` (local time).
pub fn fmt_date(unix: i64) -> String {
    let t = to_local(unix);
    let m = MONTHS.get((t.month as usize).wrapping_sub(1)).copied().unwrap_or("???");
    format!("{:02} {} {}", t.day, m, t.year)
}

/// `25 Nov 2026, 14:30:25` (local time).
pub fn fmt_datetime(unix: i64) -> String {
    format!("{}, {}", fmt_date(unix), fmt_time(unix))
}

/// Compact human duration: `45s`, `12m 5s`, `3h 12m`, `2d 4h 12m`.
pub fn fmt_duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, (secs % 86_400) / 3_600, (secs % 3_600) / 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_parse() {
        assert_eq!(parse_iso8601_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso8601_utc("2026-11-25T06:35:15.1884769Z"), Some(1_795_588_515));
        assert_eq!(parse_iso8601_utc("2000-02-29T12:00:00"), Some(951_825_600));
        assert_eq!(parse_iso8601_utc("garbage"), None);
        assert_eq!(parse_iso8601_utc("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn filetime_roundtrip() {
        let u = 1_795_588_515;
        assert_eq!(filetime_to_unix(unix_to_filetime(u)), u);
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(12 * 60 + 5), "12m 5s");
        assert_eq!(fmt_duration(3 * 3600 + 12 * 60), "3h 12m");
        assert_eq!(fmt_duration(2 * 86400 + 4 * 3600 + 12 * 60), "2d 4h 12m");
    }

    #[test]
    fn local_format_shape() {
        let s = fmt_time(1_795_588_515);
        assert_eq!(s.len(), 8);
        assert_eq!(&s[2..3], ":");
        let d = fmt_date(1_795_588_515);
        assert!(d.contains("2026"));
    }
}
