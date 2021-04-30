//! Control channel.

use crate::CONTROL_PORT;
use anyhow::{anyhow, Context, Result};
use rad_message::{ControlRequest, ControlResponse, COMMAND_PATH};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::mpsc::{Receiver, Sender};

/// Process ground control connections.
pub async fn process_connections(
    tx_requests: &Sender<ControlRequest>,
    rx_responses: &mut Receiver<ControlResponse>,
) -> Result<()> {
    let server_address = format!("0.0.0.0:{}", CONTROL_PORT);
    info!(
        "listening for ground control connections on {}",
        server_address
    );
    let listener = TcpListener::bind(server_address).await?;
    loop {
        let (socket, address) = listener.accept().await?;
        if let Err(e) = process_connection(socket, address, tx_requests, rx_responses).await {
            error!("[{}] service control connection: {}", address, e);
        }
    }
}

/// Process a ground control connection.
async fn process_connection(
    mut socket: TcpStream,
    address: SocketAddr,
    tx_requests: &Sender<ControlRequest>,
    rx_responses: &mut Receiver<ControlResponse>,
) -> Result<()> {
    info!("[{}] processing ground control connection", address);

    let mut disconnect = false;
    while !disconnect {
        let size = socket.read_u32().await.context("receive request size")?;
        let mut buffer = vec![0u8; size as _];
        socket
            .read_exact(&mut buffer)
            .await
            .context("receive request")?;
        let request: ControlRequest = bincode::deserialize(&buffer).context("decode request")?;
        debug!("control request: {}", request);

        let failure_response = request.to_failure();
        let response = match request {
            ControlRequest::NoOp => ControlResponse::NoOp,
            ControlRequest::Authenticate { .. } => {
                disconnect = true;
                failure_response
            }
            ControlRequest::Reset => ControlResponse::Reset { success: false },
            ControlRequest::Firmware => proxy_request(tx_requests, rx_responses, request)
                .await
                .unwrap_or(failure_response),
            ControlRequest::PositionVelocity => proxy_request(tx_requests, rx_responses, request)
                .await
                .unwrap_or(failure_response),
            ControlRequest::KeplerianElements => proxy_request(tx_requests, rx_responses, request)
                .await
                .unwrap_or(failure_response),
            ControlRequest::Sensors => proxy_request(tx_requests, rx_responses, request)
                .await
                .unwrap_or(failure_response),
            ControlRequest::EnableModule { .. } => {
                proxy_request(tx_requests, rx_responses, request)
                    .await
                    .unwrap_or(failure_response)
            }
            ControlRequest::UpdateModule { .. } => {
                proxy_request(tx_requests, rx_responses, request)
                    .await
                    .unwrap_or(failure_response)
            }
            ControlRequest::Maneuver { .. } => proxy_request(tx_requests, rx_responses, request)
                .await
                .unwrap_or(failure_response),
            ControlRequest::Disconnect => {
                disconnect = true;
                ControlResponse::Disconnect
            }
        };

        let buffer = bincode::serialize(&response).context("encode response")?;
        socket
            .write_u32(buffer.len() as _)
            .await
            .context("send response size")?;
        socket.write_all(&buffer).await.context("send response")?;
    }

    if disconnect {
        info!("[{}] ground control disconnect", address);
    }

    Ok(())
}

/// Proxy a request.
async fn proxy_request<Request, Response>(
    tx_requests: &Sender<Request>,
    rx_responses: &mut Receiver<Response>,
    request: Request,
) -> Result<Response> {
    tx_requests
        .send(request)
        .await
        .map_err(|_| anyhow!("send request"))?;
    rx_responses
        .recv()
        .await
        .ok_or_else(|| anyhow!("sender closed"))
}

/// Proxy control requests to firmware.
pub async fn proxy_requests_to_firmware(
    rx_requests: &mut Receiver<ControlRequest>,
    tx_responses: &Sender<ControlResponse>,
) -> Result<()> {
    info!("proxying control requests to {}", COMMAND_PATH);

    loop {
        let request = rx_requests
            .recv()
            .await
            .ok_or_else(|| anyhow!("sender closed"))?;
        let response = match proxy_request_to_firmware(&request).await {
            Ok(response) => response,
            Err(e) => {
                error!("proxy control request: {}", e);
                request.to_failure()
            }
        };
        tx_responses
            .send(response)
            .await
            .map_err(|_| anyhow!("receiver closed"))?;
    }
}

/// Proxy a request to firmware.
async fn proxy_request_to_firmware(request: &ControlRequest) -> Result<ControlResponse> {
    let mut socket = UnixStream::connect(COMMAND_PATH)
        .await
        .context("connect to control socket")?;
    let buffer = bincode::serialize(request).context("encode control request")?;
    socket
        .write_u32(buffer.len() as _)
        .await
        .context("proxy control request length")?;
    socket
        .write_all(&buffer)
        .await
        .context("proxy control request")?;
    let size = socket
        .read_u32()
        .await
        .context("proxy control response length")?;
    let mut buffer = vec![0u8; size as _];
    socket
        .read_exact(&mut buffer)
        .await
        .context("proxy control response")?;
    let response: ControlResponse =
        bincode::deserialize(&buffer).context("decode control response")?;
    Ok(response)
}
