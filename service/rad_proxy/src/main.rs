//! Rad proxy.

#[macro_use]
extern crate log;

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::dangerous_insecure_decode;
use rad_message::{ControlRequest, ControlResponse};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::digest::{digest, Digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

const RAD_AUTH_KEY: &[u8] = include_bytes!("../../data/rad_auth_key");
const TIMEOUT_SECS: u64 = 10;

/// Rad proxy.
#[derive(Clone, StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Config {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Clone, StructOpt)]
#[structopt(rename_all = "snake_case")]
enum Command {
    /// Proxy clients
    Proxy(Proxy),
    /// Manage a node
    Node(Node),
}

/// Proxy clients.
#[derive(Clone, StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Proxy {
    /// Configuration path
    #[structopt(short, long)]
    config_path: PathBuf,
}

/// Manage a node.
#[derive(Clone, StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Node {
    /// Configuration path
    #[structopt(short, long)]
    config_path: PathBuf,
}

/// Proxy configuration.
#[derive(Clone, Serialize, Deserialize)]
struct ProxyConfig {
    server_address: SocketAddr,
    service_image: String,
    auth_url: String,
    nodes: Vec<SocketAddr>,
}

/// Main.
#[tokio::main]
async fn main() {
    env_logger::init();
    let conf = Config::from_args();
    let result = match conf.command {
        Command::Proxy(ref command) => proxy_clients(command).await,
        Command::Node(ref command) => execute_node(command).await,
    };

    if let Err(e) = result {
        error!("{}", e);
    }
}

/// Proxy clients.
async fn proxy_clients(command: &Proxy) -> Result<()> {
    info!(
        "loading configuration from {}",
        command.config_path.display()
    );
    let conf_data = std::fs::read(&command.config_path)?;
    let conf: ProxyConfig = toml::from_slice(&conf_data)?;

    let listener = TcpListener::bind(&conf.server_address).await?;
    loop {
        if let Ok((socket, address)) = listener.accept().await {
            let conf = conf.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy_client(conf, socket, address).await {
                    error!("[{}] proxy client: {}", address, e);
                }
            });
        }
    }
}

/// Proxy a client.
async fn proxy_client(conf: ProxyConfig, mut client: TcpStream, address: SocketAddr) -> Result<()> {
    // Read in a request
    let request = read_request(&mut client).await?;

    // Extract the team
    let team_id = match request {
        ControlRequest::Authenticate {
            ref token,
            ref nonce,
        } => match decrypt_token(token.clone(), nonce).and_then(|xs| decode_token(&xs)) {
            Ok(x) => x,
            Err(e) => {
                warn!("[{}] {}", address, e);
                let response = request.to_failure();
                return write_response(&mut client, response).await;
            }
        },
        _ => {
            warn!("[{}] expected authentication request", address);
            let response = request.to_failure();
            return write_response(&mut client, response).await;
        }
    };

    // Find and connect to the proper node
    let team_digest = digest(&SHA256, &team_id.to_be_bytes());
    let mut team_bytes = [0u8; 8];
    team_bytes.copy_from_slice(&team_digest.as_ref()[..8]);
    let node_index = usize::from_be_bytes(team_bytes) % conf.nodes.len();
    let mut node = match TcpStream::connect(conf.nodes[node_index])
        .await
        .context("connect to node")
    {
        Ok(node) => node,
        Err(e) => {
            error!(
                "[{}] unable to connect to node {}: {}",
                address, node_index, e
            );
            let response = ControlResponse::Authenticate {
                authenticated: true,
                connected: false,
            };
            return write_response(&mut client, response).await;
        }
    };

    write_request(&mut node, request).await?;
    tokio::io::copy_bidirectional(&mut client, &mut node).await?;
    Ok(())
}

/// Decrypt a token.
fn decrypt_token(mut token: Vec<u8>, nonce: &[u8]) -> Result<String> {
    let auth_key = UnboundKey::new(&CHACHA20_POLY1305, &RAD_AUTH_KEY)
        .map_err(|_| anyhow!("create auth key"))?;
    let auth_key = LessSafeKey::new(auth_key);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| anyhow!("create nonce"))?;
    auth_key
        .open_in_place(nonce, Aad::empty(), &mut token)
        .map_err(|_| anyhow!("unseal password"))?;
    String::from_utf8(token).context("invalid UTF-8 token")
}

/// Decode a token.
fn decode_token(token: &str) -> Result<usize> {
    let data =
        dangerous_insecure_decode::<HashMap<String, String>>(&token).context("invalid token")?;
    let data = data
        .claims
        .get("user_id")
        .ok_or_else(|| anyhow!("token missing user_id field"))?;
    data.parse().context("token user_id is non-integer")
}

/// Execute a node.
async fn execute_node(command: &Node) -> Result<()> {
    info!(
        "loading configuration from {}",
        command.config_path.display()
    );
    let conf_data = std::fs::read(&command.config_path)?;
    let conf: ProxyConfig = toml::from_slice(&conf_data)?;

    let listener = TcpListener::bind(&conf.server_address).await?;
    loop {
        if let Ok((socket, address)) = listener.accept().await {
            let conf = conf.clone();
            tokio::spawn(async move {
                if let Err(e) = process_client(conf, socket, address).await {
                    error!("[{}] proxy client: {}", address, e);
                }
            });
        }
    }
}

/// Process a node client.
async fn process_client(
    conf: ProxyConfig,
    mut client: TcpStream,
    address: SocketAddr,
) -> Result<()> {
    // Read in a request
    let request = read_request(&mut client).await?;

    // Try to authenticate the client
    let team_id = match request {
        ControlRequest::Authenticate { token, nonce } => {
            let token = decrypt_token(token, &nonce)?;
            let team_id = decode_token(&token)?;
            let authenticated = authenticate_team(&conf, &token).await?;
            info!(
                "[{}] team {} authenticated: {}",
                address, team_id, authenticated
            );
            if !authenticated {
                let response = ControlResponse::Authenticate {
                    authenticated,
                    connected: false,
                };
                return write_response(&mut client, response).await;
            }
            team_id
        }
        _ => {
            warn!("[{}] expected authentication request", address);
            let response = request.to_failure();
            return write_response(&mut client, response).await;
        }
    };

    // First, try to connect.  If successful, then proceed to proxy.  If the connection fails, then
    // we assume that there is no instance or that the previous instance has terminated.  Hence, we
    // delete any existing instance and create a new one.
    let team_digest = digest(&SHA256, &team_id.to_be_bytes());
    let mut team_bytes = [0u8; 8];
    team_bytes.copy_from_slice(&team_digest.as_ref()[..8]);
    let team_index = usize::from_be_bytes(team_bytes);
    let team_port = 1024 + (team_index % 64000);
    let service_address = format!("127.0.0.1:{}", team_port);
    let mut service = if let Ok(service) = TcpStream::connect(service_address).await {
        service
    } else {
        match restart_service(&conf, &team_digest, team_port).await {
            Ok(service) => service,
            Err(e) => {
                error!(
                    "[{}] unable to connect to or start service for team {}: {}",
                    address, team_id, e
                );
                write_response(
                    &mut client,
                    ControlResponse::Authenticate {
                        authenticated: true,
                        connected: false,
                    },
                )
                .await?;
                return Ok(());
            }
        }
    };

    write_response(
        &mut client,
        ControlResponse::Authenticate {
            authenticated: true,
            connected: true,
        },
    )
    .await?;
    tokio::io::copy_bidirectional(&mut client, &mut service).await?;
    Ok(())
}

/// Authenticate a team.
async fn authenticate_team(conf: &ProxyConfig, token: &str) -> Result<bool> {
    let url = format!("{}/{}", conf.auth_url, token);
    let client = reqwest::Client::builder().build().context("HTTPS client")?;
    let response = timeout(Duration::from_secs(10), client.get(&url).send())
        .await
        .context("authentication get")??;
    Ok(response.status().as_u16() == 200)
}

/// Restart a service.
async fn restart_service(
    conf: &ProxyConfig,
    team_digest: &Digest,
    team_port: usize,
) -> Result<TcpStream> {
    let wait_time = Duration::from_secs(TIMEOUT_SECS);
    let team_id = hex::encode(&team_digest.as_ref());
    let team_hostname = format!("team-{}", team_id);
    let service_port = format!("127.0.0.1:{}", team_port);
    let service_port_str = format!("{}:1337/tcp", service_port);
    let container = format!("dc2021q-rad-{}", team_id);
    // let mut p = tokio::process::Command::new("podman")
    //     .args(&["rm", "-f", "-i", &container])
    //     .spawn()?;
    // timeout(wait_time, p.wait()).await;
    let mut p = tokio::process::Command::new("podman")
        .args(&[
            "run",
            "-d",
            "--restart=no",
            "--cap-add=SYS_PTRACE",
            "--cpus=2",
            "--memory=1G",
            "--replace",
            "--ulimit",
            "nproc=256:256,nofile=4096:4096",
            "--name",
            &container,
            "--hostname",
            &team_hostname,
            "-p",
            &service_port_str,
            &conf.service_image,
        ])
        .spawn()?;
    timeout(wait_time, p.wait()).await??;
    let socket = TcpStream::connect(&service_port).await?;
    Ok(socket)
}

/// Read a request.
async fn read_request(socket: &mut TcpStream) -> Result<ControlRequest> {
    let wait_time = Duration::from_secs(TIMEOUT_SECS);
    let size = timeout(wait_time, socket.read_u32())
        .await
        .context("read request size")??;
    let mut buffer = vec![0u8; size as _];
    timeout(wait_time, socket.read_exact(&mut buffer))
        .await
        .context("read request")??;
    bincode::deserialize(&buffer).context("decode request")
}

/// Write a request.
async fn write_request(socket: &mut TcpStream, request: ControlRequest) -> Result<()> {
    let wait_time = Duration::from_secs(TIMEOUT_SECS);
    let buffer = bincode::serialize(&request)?;
    timeout(wait_time, socket.write_u32(buffer.len() as _))
        .await
        .context("send request size")??;
    timeout(wait_time, socket.write_all(&buffer))
        .await
        .context("send request")??;
    Ok(())
}

/// Send a response.
async fn write_response(socket: &mut TcpStream, response: ControlResponse) -> Result<()> {
    let wait_time = Duration::from_secs(TIMEOUT_SECS);
    let buffer = bincode::serialize(&response)?;
    timeout(wait_time, socket.write_u32(buffer.len() as _))
        .await
        .context("send response size")??;
    timeout(wait_time, socket.write_all(&buffer))
        .await
        .context("send response")??;
    Ok(())
}
