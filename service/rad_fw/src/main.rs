//! Radiation-hardened exploitation challenge.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate solana_rbpf as rbpf;

use crate::data::{Event, Module, U64};
use rad_message::{
    ControlResponse, ExecutiveRequest, ExecutiveResponse, CHECKPOINT_PATH, MAX_MESSAGE_SIZE,
};
use rbpf::error::EbpfError;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{channel, RecvError, SendError, TryRecvError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

mod array;
mod control;
mod data;
mod scrub;
mod service;
mod vm;
mod watchdog;

const REPORT_INTERVAL: u64 = 10;
const RAD_PUB_KEY_BYTES: &[u8] = include_bytes!("../../data/rad_pub_key");

lazy_static! {
    static ref RAD_PUB_KEY: UnparsedPublicKey<&'static [u8]> =
        UnparsedPublicKey::new(&ED25519, RAD_PUB_KEY_BYTES);
}

/// Radiation error.
#[derive(Debug, Error)]
pub enum RadError {
    #[error("channel dropped during receive")]
    ChannelReceive,
    #[error("channel dropped during send")]
    ChannelSend,
    #[error("checksum failure: stored={0:016x} != computed={1:016x}")]
    Checksum(u64, u64),
    #[error("critical data error: {0}")]
    Data(String),
    #[error("ECC error")]
    Ecc(#[from] reed_solomon_erasure::Error),
    #[error("encoding error")]
    Encode(#[from] bincode::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("failed to acquire lock")]
    Mutex,
    #[error("control protocol error: {0}")]
    Protocol(String),
    #[error("repair error: {0}")]
    Repair(String),
    #[error("time error")]
    Time(#[from] std::time::SystemTimeError),
    #[error("VM error")]
    Vm(String),
    #[error("watchdog timeout")]
    Watchdog,
}

impl From<RecvError> for RadError {
    fn from(_: RecvError) -> Self {
        RadError::ChannelReceive
    }
}

impl<T> From<SendError<T>> for RadError {
    fn from(_: SendError<T>) -> Self {
        RadError::ChannelSend
    }
}

impl<T> From<PoisonError<T>> for RadError {
    fn from(_: PoisonError<T>) -> Self {
        RadError::Mutex
    }
}

impl<T> From<EbpfError<T>> for RadError
where
    T: rbpf::error::UserDefinedError,
{
    fn from(e: EbpfError<T>) -> Self {
        RadError::Vm(e.to_string())
    }
}

/// State.
#[derive(Serialize, Deserialize)]
#[repr(align(4096))]
pub struct State {
    /// Number of repairs performed
    repairs: U64,
    /// Number of restarts performed
    restarts: U64,
    /// Event log pointer
    event_index: U64,
    /// Event log
    events: [Event; 32],
    /// Modules
    modules: [Module; 4],
}

impl State {
    fn new() -> Result<Self, RadError> {
        let state = Self {
            repairs: U64::new(0)?,
            restarts: U64::new(0)?,
            event_index: U64::new(0)?,
            events: [
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
                Event::new()?,
            ],
            modules: [
                Module::new()?,
                Module::new()?,
                Module::new()?,
                Module::new()?,
            ],
        };
        Ok(state)
    }

    /// Make modules executable.
    fn make_executable(&mut self) {
        let page_addr = self as *mut State;
        let mut size = std::mem::size_of::<State>();
        if size % 4096 != 0 {
            size += 4096 - (size % 4096);
        }
        unsafe {
            if libc::mprotect(
                page_addr as *mut _,
                size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ) != 0
            {
                panic!("mprotect");
            }
        }
    }

    /// Log an event.
    pub fn log(&mut self, message: &str) {
        let mut index = self.event_index.get().unwrap_or(0) as usize;
        if index > self.events.len() {
            index = 0;
        }

        if let Some(e) = self.events.get_mut(index) {
            // Nasty nasty -- the message (flag buffer) has to be at least MAX_MESSAGE_SIZE, which
            // can be controlled from the eBPF return value
            let t = SystemTime::now();
            let mut size = message.len();
            if size > MAX_MESSAGE_SIZE {
                size = MAX_MESSAGE_SIZE;
            }
            let _ = e.update(
                t.duration_since(UNIX_EPOCH)
                    .map(|x| x.as_secs())
                    .unwrap_or(0),
                &message.as_bytes()[..size],
            );
        }
    }
}

/// Main.
fn main() {
    if let Err(e) = execute() {
        error!("{:?}", e);
    }
}

/// Execute the main loop.
fn execute() -> Result<(), RadError> {
    env_logger::init();

    let checkpoint_path = Path::new(CHECKPOINT_PATH);
    let mut state = if checkpoint_path.is_file() {
        match load_checkpoint(checkpoint_path) {
            Ok(state) => state,
            Err(e) => {
                warn!("checkpoint load error: {}", e);
                info!(
                    "removing corrupted checkpoint at {}",
                    checkpoint_path.display()
                );
                if let Err(e) = std::fs::remove_file(checkpoint_path) {
                    error!("unable to remove checkpoint: {}", e);
                }
                Box::new(State::new()?)
            }
        }
    } else {
        Box::new(State::new()?)
    };
    // state.make_executable();
    let state_ptr = state.as_ref() as *const State;
    info!("loaded protected state at {:#?}-{:#?}", state_ptr, unsafe {
        state_ptr.add(1)
    });

    // Create watchdogs
    let main_wd = Arc::new(Mutex::new(Instant::now()));
    spawn({
        let main_wd = main_wd.clone();
        move || watchdog::watchdog(vec![main_wd])
    });

    let (tx_control_requests, rx_control_requests) = channel();
    let (tx_control_responses, rx_control_responses) = channel();
    spawn(move || control::process_requests(tx_control_requests, rx_control_responses));

    let (tx_exec_requests, rx_exec_requests) = channel();
    let (tx_exec_responses, rx_exec_responses) = channel();
    spawn(move || service::proxy_requests(rx_exec_requests, tx_exec_responses));

    info!("creating initial protected state checkpoint");
    tx_exec_requests.send(ExecutiveRequest::Checkpoint {
        state: bincode::serialize(state.as_ref())?,
    })?;

    let mut last_report_ts = SystemTime::now();
    loop {
        // Kick the watchdog
        *main_wd.lock().map_err(|_| RadError::Mutex)? = Instant::now();

        // Check if we should report
        if last_report_ts.elapsed()?.as_secs() > REPORT_INTERVAL {
            for (i, module) in state.modules.iter_mut().enumerate() {
                debug!(
                    "module {:02}: enabled={} verified={} code[..16]={}...",
                    i,
                    module.is_enabled()?,
                    module.is_verified()?,
                    hex::encode(&module.code[..16])
                )
            }
            tx_exec_requests.send(ExecutiveRequest::Checkpoint {
                state: bincode::serialize(state.as_ref())?,
            })?;
            last_report_ts = SystemTime::now();
        }

        // Run dynamic modules
        let mut module_results = vec![];
        let mut module_errors = vec![];
        for (i, m) in state.modules.iter_mut().enumerate() {
            match m.execute() {
                Ok(data) => {
                    if !data.is_empty() {
                        module_results.push((i, data));
                    }
                }
                Err(e) => {
                    module_errors.push(format!("module {} exec error: {}", i, e));
                    m.set_enabled(false)?;
                }
            }
        }
        for (i, data) in module_results {
            state.log(&format!("module {} result: {}", i, hex::encode(data)));
        }
        for e in module_errors {
            state.log(&e);
            error!("{}", e);
        }

        // Check the service channel
        match rx_exec_responses.try_recv() {
            Ok(ExecutiveResponse::Checkpoint { success }) => {
                info!("checkpoint success={}", success);
            }
            Ok(ExecutiveResponse::PositionVelocity { success, t, p, v }) => {
                tx_control_responses.send(ControlResponse::PositionVelocity {
                    success,
                    t,
                    p,
                    v,
                })?;
            }
            Ok(ExecutiveResponse::KeplerianElements {
                success,
                dt,
                sma,
                ecc,
                inc,
                raan,
                aop,
                ta,
            }) => tx_control_responses.send(ControlResponse::KeplerianElements {
                success,
                dt,
                sma,
                ecc,
                inc,
                raan,
                aop,
                ta,
            })?,
            Ok(ExecutiveResponse::Sensors {
                success,
                fuel,
                radiation,
            }) => tx_control_responses.send(ControlResponse::Sensors {
                success,
                fuel,
                radiation,
            })?,
            Ok(ExecutiveResponse::Maneuver { success }) => {
                tx_control_responses.send(ControlResponse::Maneuver { success })?
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                return Err(RadError::ChannelReceive);
            }
        }

        // Check the ground channel
        match rx_control_requests.try_recv() {
            Ok(request) => {
                if let Some(response) =
                    control::process_request(&mut state, request, &tx_exec_requests)?
                {
                    match response {
                        ControlResponse::EnableModule { .. }
                        | ControlResponse::UpdateModule { .. } => {
                            info!("creating protected state checkpoint");
                            tx_exec_requests.send(ExecutiveRequest::Checkpoint {
                                state: bincode::serialize(state.as_ref())?,
                            })?;
                        }
                        _ => (),
                    }
                    tx_control_responses.send(response)?;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                return Err(RadError::ChannelReceive);
            }
        }

        // Scrub memory
        scrub::check_state(&mut state)?;

        sleep(Duration::from_millis(500));
    }
}

/// Load protected state from a checkpoint.
fn load_checkpoint<P>(path: P) -> Result<Box<State>, RadError>
where
    P: AsRef<Path>,
{
    let input = File::open(path.as_ref())?;
    let mut state: Box<State> = bincode::deserialize_from(input)?;
    state.restarts.increment(1)?;
    for module in &mut state.modules {
        module.verify_code()?;
        module.set_enabled(false)?;
    }
    Ok(state)
}

/// Reset the firmware.
fn reset() {
    std::process::exit(13);
}
