//! Service requests.

use crate::{reset, RadError};
use byteorder::{ReadBytesExt, WriteBytesExt, BE};
use rad_message::{ExecutiveRequest, ExecutiveResponse, SERVICE_PATH};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};

/// Proxy service requests.
pub fn proxy_requests(
    rx_exec_requests: Receiver<ExecutiveRequest>,
    tx_exec_responses: Sender<ExecutiveResponse>,
) -> Result<(), RadError> {
    if let Err(e) = do_proxy_requests(rx_exec_requests, tx_exec_responses) {
        error!("proxy service requests: {:?}", e);
        reset();
    }
    Ok(())
}

/// Proxy service requests.
fn do_proxy_requests(
    rx_exec_requests: Receiver<ExecutiveRequest>,
    tx_exec_responses: Sender<ExecutiveResponse>,
) -> Result<(), RadError> {
    info!("proxying service requests to {}", SERVICE_PATH);
    let mut socket = UnixStream::connect(SERVICE_PATH)?;
    loop {
        let request = rx_exec_requests.recv()?;
        debug!("executive request: {}", request);
        let buffer = bincode::serialize(&request)?;
        socket.write_u32::<BE>(buffer.len() as _)?;
        socket.write_all(&buffer)?;
        let size = socket.read_u32::<BE>()?;
        let mut buffer = vec![0u8; size as _];
        socket.read_exact(&mut buffer)?;
        let response: ExecutiveResponse = bincode::deserialize(&buffer)?;
        tx_exec_responses.send(response)?;
    }
}
