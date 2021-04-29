//! Service channel.

use crate::{BURNS, RAD, STATE};
use anyhow::{anyhow, Context, Result};
use rad_message::{ExecutiveRequest, ExecutiveResponse, CHECKPOINT_PATH, SERVICE_PATH};
use std::io::Write;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Process firmware connections.
pub async fn process_connections() -> Result<()> {
    info!("listening for firmware requests on {}", SERVICE_PATH);
    let service_path = Path::new(SERVICE_PATH);
    if service_path.exists() {
        std::fs::remove_file(service_path).context("remove firmware socket")?;
    }
    let listener = UnixListener::bind(service_path)?;
    loop {
        let (socket, _address) = listener.accept().await?;
        if let Err(e) = process_connection(socket).await {
            error!("service firmware connection: {}", e);
        }
    }
}

/// Process a firmware connection.
async fn process_connection(mut socket: UnixStream) -> Result<()> {
    info!("processing firmware service connection");
    loop {
        let size = socket.read_u32().await.context("receive request size")?;
        let mut buffer = vec![0u8; size as _];
        socket
            .read_exact(&mut buffer)
            .await
            .context("receive request")?;
        let request: ExecutiveRequest = bincode::deserialize(&buffer).context("decode request")?;
        debug!("firmware request: {}", request);

        let response = match request {
            ExecutiveRequest::Checkpoint { state } => {
                let mut output =
                    tempfile::NamedTempFile::new().context("create temporary checkpoint")?;
                output
                    .write_all(&state)
                    .context("write temporary checkpoint")?;
                // output
                //     .persist(CHECKPOINT_PATH)
                //     .context("persist checkpoint")?;
                output.flush().context("flush temporary checkpoint")?;
                std::fs::copy(output, CHECKPOINT_PATH).context("persist checkpoint")?;
                ExecutiveResponse::Checkpoint { success: true }
            }
            ExecutiveRequest::PositionVelocity => {
                if let Ok(Some(state)) = STATE.lock().map(|x| *x) {
                    ExecutiveResponse::PositionVelocity {
                        success: true,
                        t: state.orbit.dt.as_utc_seconds() as u64,
                        p: (state.orbit.x, state.orbit.y, state.orbit.z),
                        v: (state.orbit.vx, state.orbit.vy, state.orbit.vz),
                    }
                } else {
                    ExecutiveResponse::PositionVelocity {
                        success: false,
                        t: 0,
                        p: (0.0, 0.0, 0.0),
                        v: (0.0, 0.0, 0.0),
                    }
                }
            }
            ExecutiveRequest::KeplerianElements => {
                if let Ok(Some(state)) = STATE.lock().map(|x| *x) {
                    ExecutiveResponse::KeplerianElements {
                        success: true,
                        dt: state.orbit.dt.as_utc_seconds() as u64,
                        sma: state.orbit.sma(),
                        ecc: state.orbit.ecc(),
                        inc: state.orbit.inc(),
                        raan: state.orbit.raan(),
                        aop: state.orbit.aop(),
                        ta: state.orbit.ta(),
                    }
                } else {
                    ExecutiveResponse::KeplerianElements {
                        success: false,
                        dt: 0,
                        sma: 0.0,
                        ecc: 0.0,
                        inc: 0.0,
                        raan: 0.0,
                        aop: 0.0,
                        ta: 0.0,
                    }
                }
            }
            ExecutiveRequest::Sensors => {
                if let Ok(Some(state)) = STATE.lock().map(|x| *x) {
                    ExecutiveResponse::Sensors {
                        success: true,
                        fuel: state.fuel_mass,
                        radiation: *RAD.lock().map_err(|_| anyhow!("flux lock"))?,
                    }
                } else {
                    ExecutiveResponse::Sensors {
                        success: false,
                        fuel: 0.0,
                        radiation: 0.0,
                    }
                }
            }
            ExecutiveRequest::Maneuver { burns } => {
                debug!("setting burn schedule: {:#?}", burns);
                *BURNS.lock().map_err(|_| anyhow!("burns lock"))? = Some(burns);
                ExecutiveResponse::Maneuver { success: true }
            }
        };
        let buffer = bincode::serialize(&response).context("encode response")?;
        socket
            .write_u32(buffer.len() as _)
            .await
            .context("send response size")?;
        socket.write_all(&buffer).await.context("send response")?;
    }
}
