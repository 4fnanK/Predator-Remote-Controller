//! Small, dependency-free helpers shared by every module.

pub mod rand;
pub mod time;
pub mod win;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A generation-counting wake-up signal (condition variable without lost wake-ups).
///
/// Producers call [`Signal::notify`]; a consumer remembers the generation it has seen and
/// calls [`Signal::wait_changed`] to sleep until the generation moves on (or a timeout).
#[derive(Default)]
pub struct Signal {
    generation: Mutex<u64>,
    cv: Condvar,
}

impl Signal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wake every waiter.
    pub fn notify(&self) {
        let mut g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        self.cv.notify_all();
    }

    /// Current generation.
    pub fn generation(&self) -> u64 {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Block until the generation differs from `seen` or `timeout` elapses.
    /// Returns the generation observed on return (equal to `seen` on timeout).
    pub fn wait_changed(&self, seen: u64, timeout: Duration) -> u64 {
        let deadline = Instant::now() + timeout;
        let mut g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        while *g == seen {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (ng, _res) = self.cv.wait_timeout(g, deadline - now).unwrap_or_else(|e| e.into_inner());
            g = ng;
        }
        *g
    }
}

/// Process-wide stop flag. Stopping notifies every registered [`Signal`] and sets a manual-reset
/// Win32 event so threads blocked in `WaitForMultipleObjects` wake up too.
pub struct StopFlag {
    stopped: AtomicBool,
    signals: Mutex<Vec<Arc<Signal>>>,
    event: win::OwnedEvent,
}

impl StopFlag {
    pub fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            signals: Mutex::new(Vec::new()),
            event: win::OwnedEvent::new_manual().expect("CreateEventW failed"),
        }
    }

    /// Register a signal that must be notified when stopping.
    pub fn register(&self, s: Arc<Signal>) {
        self.signals.lock().unwrap_or_else(|e| e.into_inner()).push(s);
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.event.set();
        for s in self.signals.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            s.notify();
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Raw manual-reset event handle that becomes signaled on stop (for WaitForMultipleObjects).
    pub fn event_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.event.raw()
    }

    /// Sleep up to `d`; returns `true` if a stop was requested (early wake-up).
    pub fn sleep(&self, d: Duration) -> bool {
        if self.is_stopped() {
            return true;
        }
        self.event.wait(d);
        self.is_stopped()
    }
}

impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}

/// Exponential backoff with full jitter-free doubling, capped.
#[derive(Debug, Clone)]
pub struct Backoff {
    current: Duration,
    min: Duration,
    max: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self { current: min, min, max }
    }

    /// Next delay to wait; doubles the internal delay for the following call.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        self.current = (self.current * 2).min(self.max);
        // add up to 10% jitter derived from the clock to avoid synchronized retries
        let frac = (crate::util::time::now_unix_millis().rem_euclid(1000)) as u64; // 0..=999
        let jitter = d.as_millis() as u64 * frac / 10_000;
        d + Duration::from_millis(jitter)
    }

    pub fn reset(&mut self) {
        self.current = self.min;
    }

    pub fn current(&self) -> Duration {
        self.current
    }
}

/// Truncate a string to at most `max` characters (not bytes), appending an ellipsis if cut.
pub fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_wakes_and_times_out() {
        let s = Arc::new(Signal::new());
        let g = s.generation();
        assert_eq!(s.wait_changed(g, Duration::from_millis(10)), g);
        let s2 = s.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            s2.notify();
        });
        let ng = s.wait_changed(g, Duration::from_secs(5));
        assert_ne!(ng, g);
        t.join().unwrap();
    }

    #[test]
    fn backoff_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
        let mut last = Duration::ZERO;
        for _ in 0..10 {
            last = b.next_delay();
        }
        assert!(last >= Duration::from_secs(8) && last <= Duration::from_millis(8_900));
        b.reset();
        assert!(b.next_delay() < Duration::from_millis(1_200));
    }

    #[test]
    fn stop_flag_wakes_sleep() {
        let f = Arc::new(StopFlag::new());
        let f2 = f.clone();
        let t = std::thread::spawn(move || f2.sleep(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(20));
        f.stop();
        assert!(t.join().unwrap());
    }

    #[test]
    fn truncate() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        assert_eq!(truncate_chars("hello world", 6), "hello…");
    }
}
