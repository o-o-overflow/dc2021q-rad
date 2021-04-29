//! Software watchdog.

use crate::{reset, RadError};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

const WATCHDOG_TIMEOUT: u64 = 10;

/// Watchdog thread.
pub fn watchdog(timers: Vec<Arc<Mutex<Instant>>>) {
    if let Err(e) = do_watchdog(&timers) {
        error!("watchdog: {:?}", e);
        reset();
    }
}

/// Watchdog thread.
fn do_watchdog(timers: &[Arc<Mutex<Instant>>]) -> Result<(), RadError> {
    debug!("executing watchdog thread");

    loop {
        sleep(Duration::from_secs(1));
        for timer in timers.iter() {
            if timer
                .lock()
                .map_err(|_| RadError::Mutex)?
                .elapsed()
                .as_secs()
                > WATCHDOG_TIMEOUT
            {
                return Err(RadError::Watchdog);
            }
        }
    }
}
