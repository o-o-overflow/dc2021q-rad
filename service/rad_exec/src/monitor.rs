//! Monitor firmware.

use crate::{FIRMWARE_PATH, RAD};
use anyhow::{anyhow, Context, Result};
use rad_message::CHECKPOINT_PATH;
use rand::Rng;
use regex::Regex;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout, Command};
use tokio::time::sleep;

/// Execute and monitor the firmware.
pub async fn execute_firmware() -> Result<()> {
    info!("executing firmware at {}", FIRMWARE_PATH);
    let mut p = Command::new(&FIRMWARE_PATH);
    p.stdout(Stdio::piped()).stderr(Stdio::piped());
    let checkpoint_path = Path::new(CHECKPOINT_PATH);
    if checkpoint_path.is_file() {
        p.arg(checkpoint_path);
    }

    let mut p = p.spawn().context("execute firmware")?;
    if let (Some(id), Some(stdout), Some(stderr)) = (p.id(), p.stdout.take(), p.stderr.take()) {
        tokio::spawn(async move {
            if let Err(e) = inject_faults(id, stdout, stderr).await {
                error!("inject faults: {}", e);
            }
        });
    }

    let status = p.wait().await.context("wait for firmware exit")?;
    info!("firmware exited with status: {}", status);
    Ok(())
}

/// Inject memory faults into firmware.
async fn inject_faults(id: u32, _stdout: ChildStdout, stderr: ChildStderr) -> Result<()> {
    info!("waiting for protected state address in process {}", id);
    let addr_re = Regex::new(r"protected state at 0x([[:xdigit:]]+)-0x([[:xdigit:]]+)")?;
    let mut reader = BufReader::new(stderr).lines();
    let mut state_addr = 0;
    let mut state_size = 0;
    while let Some(line) = reader.next_line().await? {
        info!("FW: {}", line);
        if let Some(m) = addr_re.captures(&line) {
            if let (Some(start), Some(end)) = (m.get(1), m.get(2)) {
                state_addr = u64::from_str_radix(start.as_str(), 16)?;
                state_size = u64::from_str_radix(end.as_str(), 16)? - state_addr;
                break;
            }
        }
    }

    tokio::spawn(async move {
        while let Ok(Some(line)) = reader.next_line().await {
            info!("FW: {}", line);
        }
    });

    if state_addr != 0 {
        info!(
            "injecting faults into protected state at 0x{:x}",
            state_addr
        );

        loop {
            sleep(Duration::from_millis(100)).await;

            let mut rng = rand::thread_rng();
            let radiation = *RAD.lock().map_err(|_| anyhow!("radiation lock"))? as usize;
            if rng.gen_range(0..300) < radiation {
                let fault_addr = rng.gen_range(state_addr..(state_addr + state_size)) & (!0x0f);
                let fault_bit = rng.gen_range(0..64);
                // debug!("flipping bit at 0x{:x}/{}", fault_addr, fault_bit);
                unsafe {
                    let mut x: [u64; 1] = [0];
                    let mut local_iovec: libc::iovec = std::mem::zeroed();
                    local_iovec.iov_base = x.as_mut_ptr() as *mut _;
                    local_iovec.iov_len = 8;
                    let mut remote_iovec: libc::iovec = std::mem::zeroed();
                    remote_iovec.iov_base = fault_addr as *mut _;
                    remote_iovec.iov_len = 8;
                    if libc::process_vm_readv(id as i32, &local_iovec, 1, &remote_iovec, 1, 0) != 8
                    {
                        return Err(anyhow!(
                            "unable to read memory at 0x{:x}/{}",
                            fault_addr,
                            fault_bit
                        ));
                    }
                    x[0] ^= 1 << fault_bit;
                    if libc::process_vm_writev(id as i32, &local_iovec, 1, &remote_iovec, 1, 0) != 8
                    {
                        return Err(anyhow!(
                            "unable to write memory at 0x{:x}/{}",
                            fault_addr,
                            fault_bit
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}
