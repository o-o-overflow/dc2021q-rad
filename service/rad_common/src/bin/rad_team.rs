use jsonwebtoken::dangerous_insecure_decode;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

/// Output team identifiers
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Config {
    /// Number of nodes
    #[structopt(short, long, default_value = "4")]
    nodes: usize,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
enum Command {
    AllTeams(AllTeams),
    FromTeam(FromTeam),
    ToTeam(ToTeam),
    TestAuth(TestAuth),
}

/// Convert from a team ID to identifiers
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct AllTeams {
    /// Max team ID
    #[structopt(short, long, default_value = "1024")]
    max_id: usize,
}

/// Convert from a team ID to identifiers
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct FromTeam {
    /// Token
    #[structopt()]
    token: String,
}

/// Convert from a team port to identifiers
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct ToTeam {
    /// Team port
    #[structopt()]
    port: u16,
}

/// Test authentication
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct TestAuth {
    /// Auth URL
    #[structopt(short, long, default_value = "https://e4q2x916mg.execute-api.us-east-2.amazonaws.com/production/challenge/rad")]
    auth_url: String,
    /// Token
    #[structopt()]
    token: String,
}

/// Token.
#[derive(Serialize, Deserialize)]
struct Token {
    // access: String,
    user_id: usize,
}

fn main() {
    let conf = Config::from_args();
    match conf.command {
        Command::AllTeams(ref cmd) => {
            for i in 0..cmd.max_id {
                let (node_index, team_port) = get_identifiers(i, conf.nodes);
                println!("team={} node={} port={}", i, node_index, team_port);
            }
        }
        Command::FromTeam(ref cmd) => {
            let data = dangerous_insecure_decode::<Token>(&cmd.token).expect("decode");
            let (node_index, team_port) = get_identifiers(data.claims.user_id, conf.nodes);
            println!(
                "team={} node={} port={}",
                data.claims.user_id, node_index, team_port
            );
        }
        Command::ToTeam(ref cmd) => {
            for i in 0..1024 {
                let (node_index, team_port) = get_identifiers(i, conf.nodes);
                if team_port == cmd.port as usize {
                    println!("team={} node={} port={}", i, node_index, team_port);
                }
            }
        }
        Command::TestAuth(ref cmd) => {
            let url = format!("{}/{}", cmd.auth_url, cmd.token);
            let data = dangerous_insecure_decode::<Token>(&cmd.token).expect("decode");
            let response = reqwest::blocking::get(url).expect("get");
            println!("team={} authenticated={}", data.claims.user_id, response.status().is_success());
        }
    }
}

fn get_identifiers(id: usize, nodes: usize) -> (usize, usize) {
    let team_digest = digest(&SHA256, &id.to_be_bytes());
    let mut team_bytes = [0u8; 8];
    team_bytes.copy_from_slice(&team_digest.as_ref()[..8]);
    let team_index = usize::from_be_bytes(team_bytes);
    let node_index = team_index % nodes;
    let team_port = 1024 + (team_index % 64000);
    (node_index, team_port)
}
