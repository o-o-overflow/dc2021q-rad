//! Control channel.

use crate::data::hash;
use crate::{reset, RadError, State};
use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use rad_message::{
    ControlRequest, ControlResponse, ExecutiveRequest, ModuleStatus, COMMAND_PATH, MAX_MESSAGE_SIZE,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{SystemTime, UNIX_EPOCH};

/// Process control requests.
pub fn process_requests(
    tx_requests: Sender<ControlRequest>,
    rx_responses: Receiver<ControlResponse>,
) {
    if let Err(e) = do_process_requests(tx_requests, rx_responses) {
        error!("control channel: {:?}", e);
        reset();
    }
}

/// Process control requests.
fn do_process_requests(
    tx_requests: Sender<ControlRequest>,
    rx_responses: Receiver<ControlResponse>,
) -> Result<(), RadError> {
    info!("listening for control requests at {}", COMMAND_PATH);
    let command_path = Path::new(COMMAND_PATH);
    if command_path.exists() {
        std::fs::remove_file(command_path)?;
    }

    let listener = UnixListener::bind(command_path)?;
    loop {
        match listener.accept() {
            Ok((mut socket, _address)) => {
                let size = socket.read_u32::<BE>()?;
                let mut buffer = vec![0u8; size as _];
                socket.read_exact(&mut buffer)?;
                let request: ControlRequest = bincode::deserialize(&buffer)?;
                debug!("control request: {}", request);
                tx_requests.send(request)?;
                let response = rx_responses.recv()?;
                let buffer = bincode::serialize(&response)?;
                socket.write_u32::<BE>(buffer.len() as _)?;
                socket.write_all(&buffer)?;
            }
            Err(e) => {
                error!("control request: {}", e);
            }
        }
    }
}

/// Process a control request.
pub fn process_request(
    state: &mut Box<State>,
    request: ControlRequest,
    tx_exec_requests: &Sender<ExecutiveRequest>,
) -> Result<Option<ControlResponse>, RadError> {
    let response = match request {
        ControlRequest::Firmware => {
            let mut events = vec![];
            for e in &mut state.events {
                let mut m = vec![0u8; MAX_MESSAGE_SIZE];
                let t = e.get(&mut m)?;
                events.push(rad_message::Event::new(t, m));
            }
            let mut modules = vec![];
            for m in &mut state.modules {
                modules.push(ModuleStatus::new(
                    m.is_enabled()?,
                    m.is_verified()?,
                    hash(&m.code)?,
                ));
            }
            Some(ControlResponse::Firmware {
                success: true,
                repairs: state.repairs.get()?,
                restarts: state.restarts.get()?,
                events,
                modules,
            })
        }
        ControlRequest::PositionVelocity => {
            tx_exec_requests.send(ExecutiveRequest::PositionVelocity)?;
            None
        }
        ControlRequest::KeplerianElements => {
            tx_exec_requests.send(ExecutiveRequest::KeplerianElements)?;
            None
        }
        ControlRequest::Sensors => {
            tx_exec_requests.send(ExecutiveRequest::Sensors)?;
            None
        }
        ControlRequest::EnableModule { id, enable } => {
            let id = id as usize;
            if let Some(m) = state.modules.get_mut(id) {
                m.set_enabled(enable)?;
                state.log(&format!("enable module {}: success", id));
                Some(ControlResponse::EnableModule { success: true })
            } else {
                state.log(&format!("enable module {}: failure", id));
                Some(ControlResponse::EnableModule { success: false })
            }
        }
        ControlRequest::UpdateModule {
            id,
            ref module,
            ref signature,
            encoded,
        } => {
            let id = id as usize;
            if let Some(m) = state.modules.get_mut(id) {
                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if m.can_update(ts)? {
                    m.set_enabled(false)?;
                    let checksum = m.update(ts, module, signature)?;
                    let verified = m.verify_code()?;
                    m.set_enabled(true)?;
                    m.set_encoded(encoded)?;
                    state.log(&format!("update module {}: success", id));
                    Some(ControlResponse::UpdateModule {
                        success: verified,
                        checksum,
                        verified,
                        enabled: true,
                    })
                } else {
                    state.log(&format!("update module {}: failure", id));
                    Some(request.to_failure())
                }
            } else {
                state.log(&format!("update module {}: failure", id));
                Some(request.to_failure())
            }
        }
        ControlRequest::Maneuver { burns } => {
            for burn in &burns {
                state.log(&format!(
                    "schedule maneuver: start={} length={}s thrust={}N vector=({}, {}, {})",
                    burn.start,
                    burn.length,
                    burn.thrust,
                    burn.vector.0,
                    burn.vector.1,
                    burn.vector.2
                ));
            }
            tx_exec_requests.send(ExecutiveRequest::Maneuver { burns })?;
            None
        }
        ControlRequest::NoOp | ControlRequest::Reset | ControlRequest::Disconnect => {
            return Err(RadError::Protocol(
                "invalid control protocol message".to_string(),
            ));
        }
    };

    Ok(response)
}
