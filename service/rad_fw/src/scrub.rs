//! Memory scrubbing.

use crate::data::Repairable;
use crate::{reset, RadError, State};
use std::thread::sleep;
use std::time::Duration;

macro_rules! check {
    ($data:expr, $repairs:ident) => {
        if !$data.verify()? {
            $data.repair()?;
            $repairs += 1;
        }
    };
}

/// Scrubbing thread.
pub fn _scrub(mut state: Box<State>) {
    if let Err(e) = _do_scrub(&mut state) {
        error!("scrub protected state: {:?}", e);
        state.log(&format!("{:?}", e));
        reset();
    }
}

/// Scrubbing thread.
fn _do_scrub(state: &mut Box<State>) -> Result<(), RadError> {
    debug!("executing scrubbing thread");

    loop {
        check_state(state)?;
        sleep(Duration::from_secs(1));
    }
}

/// Check a state for memory errors and repair them.
pub fn check_state(state: &mut Box<State>) -> Result<(), RadError> {
    let mut repairs = 0;
    check!(state.repairs, repairs);
    check!(state.restarts, repairs);
    check!(state.event_index, repairs);
    for event in &mut state.events {
        check!(event, repairs);
    }
    for module in &mut state.modules {
        check!(module, repairs);
    }
    state.repairs.increment(repairs)?;
    Ok(())
}
