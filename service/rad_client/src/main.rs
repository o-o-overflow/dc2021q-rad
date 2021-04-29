//! Rad client.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use rad_message::{ControlRequest, ControlResponse, Event, ModuleStatus};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use termion::raw::IntoRawMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tui::backend::{Backend, TermionBackend};
use tui::layout::{Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::symbols::Marker::Braille;
use tui::text::{Span, Spans};
use tui::widgets::canvas::{Canvas, Points};
use tui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph};
use tui::{Frame, Terminal};

const MAX_RADIATION_POINTS: usize = 10;
const RAD_PTS_LOW: &[(f64, f64)] = &[
    (-12.0, -4.0),
    (-12.0, -3.0),
    (-12.0, -2.0),
    (-12.0, -1.0),
    (-12.0, 0.0),
    (-12.0, 1.0),
    (-12.0, 2.0),
    (-12.0, 3.0),
    (-12.0, 4.0),
    (-11.0, -6.0),
    (-11.0, -5.0),
    (-11.0, -4.0),
    (-11.0, -3.0),
    (-11.0, 3.0),
    (-11.0, 4.0),
    (-11.0, 5.0),
    (-11.0, 6.0),
    (-10.0, -7.0),
    (-10.0, -6.0),
    (-10.0, 6.0),
    (-10.0, 7.0),
    (-9.0, -9.0),
    (-9.0, -8.0),
    (-9.0, -7.0),
    (-9.0, -2.0),
    (-9.0, -1.0),
    (-9.0, 0.0),
    (-9.0, 1.0),
    (-9.0, 2.0),
    (-9.0, 7.0),
    (-9.0, 8.0),
    (-9.0, 9.0),
    (-8.0, -9.0),
    (-8.0, -4.0),
    (-8.0, -3.0),
    (-8.0, -2.0),
    (-8.0, -1.0),
    (-8.0, 1.0),
    (-8.0, 2.0),
    (-8.0, 3.0),
    (-8.0, 4.0),
    (-8.0, 9.0),
    (-7.0, -10.0),
    (-7.0, -9.0),
    (-7.0, -6.0),
    (-7.0, -5.0),
    (-7.0, -4.0),
    (-7.0, 4.0),
    (-7.0, 5.0),
    (-7.0, 6.0),
    (-7.0, 9.0),
    (-7.0, 10.0),
    (-6.0, -11.0),
    (-6.0, -10.0),
    (-6.0, -7.0),
    (-6.0, -6.0),
    (-6.0, 6.0),
    (-6.0, 7.0),
    (-6.0, 10.0),
    (-6.0, 11.0),
    (-5.0, -11.0),
    (-5.0, -7.0),
    (-5.0, 7.0),
    (-5.0, 11.0),
    (-4.0, -12.0),
    (-4.0, -11.0),
    (-4.0, -8.0),
    (-4.0, -7.0),
    (-4.0, 7.0),
    (-4.0, 8.0),
    (-4.0, 11.0),
    (-4.0, 12.0),
    (-3.0, -12.0),
    (-3.0, -11.0),
    (-3.0, -8.0),
    (-3.0, 8.0),
    (-3.0, 11.0),
    (-3.0, 12.0),
    (-2.0, -12.0),
    (-2.0, -9.0),
    (-2.0, -8.0),
    (-2.0, 8.0),
    (-2.0, 9.0),
    (-2.0, 12.0),
    (-1.0, -12.0),
    (-1.0, -9.0),
    (-1.0, -8.0),
    (-1.0, 8.0),
    (-1.0, 9.0),
    (-1.0, 12.0),
    (0.0, -12.0),
    (0.0, -9.0),
    (0.0, 9.0),
    (0.0, 12.0),
    (1.0, -12.0),
    (1.0, -9.0),
    (1.0, -8.0),
    (1.0, 8.0),
    (1.0, 9.0),
    (1.0, 12.0),
    (2.0, -12.0),
    (2.0, -9.0),
    (2.0, -8.0),
    (2.0, 8.0),
    (2.0, 9.0),
    (2.0, 12.0),
    (3.0, -12.0),
    (3.0, -11.0),
    (3.0, -8.0),
    (3.0, 8.0),
    (3.0, 11.0),
    (3.0, 12.0),
    (4.0, -12.0),
    (4.0, -11.0),
    (4.0, -8.0),
    (4.0, -7.0),
    (4.0, 7.0),
    (4.0, 8.0),
    (4.0, 11.0),
    (4.0, 12.0),
    (5.0, -11.0),
    (5.0, -7.0),
    (5.0, 7.0),
    (5.0, 11.0),
    (6.0, -11.0),
    (6.0, -10.0),
    (6.0, -7.0),
    (6.0, -6.0),
    (6.0, 6.0),
    (6.0, 7.0),
    (6.0, 10.0),
    (6.0, 11.0),
    (7.0, -10.0),
    (7.0, -9.0),
    (7.0, -6.0),
    (7.0, -5.0),
    (7.0, -4.0),
    (7.0, 4.0),
    (7.0, 5.0),
    (7.0, 6.0),
    (7.0, 9.0),
    (7.0, 10.0),
    (8.0, -9.0),
    (8.0, -4.0),
    (8.0, -3.0),
    (8.0, -2.0),
    (8.0, -1.0),
    (8.0, 1.0),
    (8.0, 2.0),
    (8.0, 3.0),
    (8.0, 4.0),
    (8.0, 9.0),
    (9.0, -9.0),
    (9.0, -8.0),
    (9.0, -7.0),
    (9.0, -2.0),
    (9.0, -1.0),
    (9.0, 0.0),
    (9.0, 1.0),
    (9.0, 2.0),
    (9.0, 7.0),
    (9.0, 8.0),
    (9.0, 9.0),
    (10.0, -7.0),
    (10.0, -6.0),
    (10.0, 6.0),
    (10.0, 7.0),
    (11.0, -6.0),
    (11.0, -5.0),
    (11.0, -4.0),
    (11.0, -3.0),
    (11.0, 3.0),
    (11.0, 4.0),
    (11.0, 5.0),
    (11.0, 6.0),
    (12.0, -4.0),
    (12.0, -3.0),
    (12.0, -2.0),
    (12.0, -1.0),
    (12.0, 0.0),
    (12.0, 1.0),
    (12.0, 2.0),
    (12.0, 3.0),
    (12.0, 4.0),
];
const RAD_PTS_MED: &[(f64, f64)] = &[
    (-11.0, -2.0),
    (-11.0, -1.0),
    (-11.0, 0.0),
    (-11.0, 1.0),
    (-11.0, 2.0),
    (-10.0, -5.0),
    (-10.0, -4.0),
    (-10.0, -1.0),
    (-10.0, 0.0),
    (-10.0, 1.0),
    (-10.0, 4.0),
    (-10.0, 5.0),
    (-9.0, -6.0),
    (-9.0, -4.0),
    (-9.0, -3.0),
    (-9.0, 3.0),
    (-9.0, 4.0),
    (-9.0, 6.0),
    (-8.0, -8.0),
    (-8.0, -7.0),
    (-8.0, -6.0),
    (-8.0, -5.0),
    (-8.0, 5.0),
    (-8.0, 6.0),
    (-8.0, 7.0),
    (-8.0, 8.0),
    (-7.0, -8.0),
    (-7.0, -7.0),
    (-7.0, 7.0),
    (-7.0, 8.0),
    (-6.0, -9.0),
    (-6.0, -8.0),
    (-6.0, 8.0),
    (-6.0, 9.0),
    (-5.0, -10.0),
    (-5.0, -8.0),
    (-5.0, 8.0),
    (-5.0, 10.0),
    (-4.0, -10.0),
    (-4.0, -9.0),
    (-4.0, 9.0),
    (-4.0, 10.0),
    (-3.0, -9.0),
    (-3.0, 9.0),
    (-2.0, -11.0),
    (-2.0, 11.0),
    (-1.0, -11.0),
    (-1.0, -10.0),
    (-1.0, 10.0),
    (-1.0, 11.0),
    (0.0, -11.0),
    (0.0, -10.0),
    (0.0, 10.0),
    (0.0, 11.0),
    (1.0, -11.0),
    (1.0, -10.0),
    (1.0, 10.0),
    (1.0, 11.0),
    (2.0, -11.0),
    (2.0, 11.0),
    (3.0, -9.0),
    (3.0, 9.0),
    (4.0, -10.0),
    (4.0, -9.0),
    (4.0, 9.0),
    (4.0, 10.0),
    (5.0, -10.0),
    (5.0, -8.0),
    (5.0, 8.0),
    (5.0, 10.0),
    (6.0, -9.0),
    (6.0, -8.0),
    (6.0, 8.0),
    (6.0, 9.0),
    (7.0, -8.0),
    (7.0, -7.0),
    (7.0, 7.0),
    (7.0, 8.0),
    (8.0, -8.0),
    (8.0, -7.0),
    (8.0, -6.0),
    (8.0, -5.0),
    (8.0, 5.0),
    (8.0, 6.0),
    (8.0, 7.0),
    (8.0, 8.0),
    (9.0, -6.0),
    (9.0, -4.0),
    (9.0, -3.0),
    (9.0, 3.0),
    (9.0, 4.0),
    (9.0, 6.0),
    (10.0, -5.0),
    (10.0, -4.0),
    (10.0, -1.0),
    (10.0, 0.0),
    (10.0, 1.0),
    (10.0, 4.0),
    (10.0, 5.0),
    (11.0, -2.0),
    (11.0, -1.0),
    (11.0, 0.0),
    (11.0, 1.0),
    (11.0, 2.0),
];
const RAD_PTS_HIGH: &[(f64, f64)] = &[
    (-10.0, -3.0),
    (-10.0, -2.0),
    (-10.0, 2.0),
    (-10.0, 3.0),
    (-9.0, -5.0),
    (-9.0, 5.0),
    (-5.0, -9.0),
    (-5.0, 9.0),
    (-3.0, -10.0),
    (-3.0, 10.0),
    (-2.0, -10.0),
    (-2.0, 10.0),
    (2.0, -10.0),
    (2.0, 10.0),
    (3.0, -10.0),
    (3.0, 10.0),
    (5.0, -9.0),
    (5.0, 9.0),
    (9.0, -5.0),
    (9.0, 5.0),
    (10.0, -3.0),
    (10.0, -2.0),
    (10.0, 2.0),
    (10.0, 3.0),
];

/// Rad client.
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Config {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
enum Command {
    /// Observe a satellite
    Observe(Observe),
}

/// Observe a satellite
#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
struct Observe {
    /// Server address
    #[structopt(short, long)]
    ground_control_gateway: SocketAddr,
}

/// State.
struct State {
    log: VecDeque<(DateTime<Utc>, String)>,
    position: (f64, f64, f64),
    velocity: (f64, f64, f64),
    fuel: f64,
    repairs: u64,
    restarts: u64,
    radiation: VecDeque<f64>,
    events: Vec<Event>,
    modules: Vec<ModuleStatus>,
}

impl State {
    fn new() -> Self {
        Self {
            log: VecDeque::new(),
            position: (0.0, 0.0, 0.0),
            velocity: (0.0, 0.0, 0.0),
            fuel: 0.0,
            repairs: 0,
            restarts: 0,
            radiation: VecDeque::new(),
            events: vec![],
            modules: vec![],
        }
    }

    fn log_message(&mut self, message: String) {
        self.log.push_back((Utc::now(), message));
        if self.log.len() > 100 {
            self.log.pop_front();
        }
    }
}

/// Main.
#[tokio::main]
async fn main() {
    let conf = Config::from_args();
    let result = match conf.command {
        Command::Observe(ref command) => observe_satellite(command),
    };
    if let Err(e) = result.await {
        eprintln!("{}", e);
    }
}

/// Observe a satellite.
async fn observe_satellite(command: &Observe) -> Result<()> {
    let stdout = std::io::stdout().into_raw_mode()?;
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state = Arc::new(Mutex::new(State::new()));
    state
        .lock()
        .map_err(|_| anyhow!("state lock"))?
        .log_message("initializing observation system".to_string());

    tokio::spawn(poll_satellite(
        state.clone(),
        command.ground_control_gateway,
    ));

    terminal.clear()?;
    loop {
        if let Ok(state) = state.lock() {
            terminal.draw(|f| draw_ui(f, &state))?;
        }
        sleep(Duration::from_secs(1)).await;
    }
}

/// Poll the satellite status.
async fn poll_satellite(state: Arc<Mutex<State>>, address: SocketAddr) -> Result<()> {
    loop {
        if let Err(e) = connect_satellite(state.clone(), address).await {
            state
                .lock()
                .map_err(|_| anyhow!("state lock"))?
                .log_message(format!("ground channel error: {}", e));
            sleep(Duration::from_secs(1)).await;
        }
    }
}

/// Run a satellite ground control connection.
async fn connect_satellite(state: Arc<Mutex<State>>, address: SocketAddr) -> Result<()> {
    state
        .lock()
        .map_err(|_| anyhow!("state lock"))?
        .log_message(format!(
            "establishing ground control channel to {}",
            address
        ));
    let mut socket = TcpStream::connect(address).await.context("connect error")?;
    loop {
        let response = send_request(&mut socket, &ControlRequest::PositionVelocity).await?;
        match response {
            ControlResponse::PositionVelocity { success, p, v, .. } => {
                let mut state = state.lock().map_err(|_| anyhow!("state lock"))?;
                if success {
                    state.position = p;
                    state.velocity = v;
                } else {
                    state.log_message("position and velocity request failed".to_owned());
                }
            }
            _ => return Err(anyhow!("expected position and velocity response")),
        }

        let response = send_request(&mut socket, &ControlRequest::Firmware).await?;
        match response {
            ControlResponse::Firmware {
                success,
                repairs,
                restarts,
                events,
                modules,
            } => {
                let mut state = state.lock().map_err(|_| anyhow!("state lock"))?;
                if success {
                    state.repairs = repairs;
                    state.restarts = restarts;
                    state.events = events;
                    state.modules = modules;
                } else {
                    state.log_message("status request failed".to_owned());
                }
            }
            _ => return Err(anyhow!("expected status response")),
        }

        let response = send_request(&mut socket, &ControlRequest::Sensors).await?;
        match response {
            ControlResponse::Sensors {
                success,
                fuel,
                radiation,
            } => {
                let mut state = state.lock().map_err(|_| anyhow!("state lock"))?;
                if success {
                    state.fuel = fuel;
                    state.radiation.push_back(radiation);
                    if state.radiation.len() > MAX_RADIATION_POINTS {
                        state.radiation.pop_front();
                    }
                } else {
                    state.log_message("radiation level request failed".to_owned());
                }
            }
            _ => return Err(anyhow!("expected status response")),
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Send a control request.
async fn send_request(socket: &mut TcpStream, request: &ControlRequest) -> Result<ControlResponse> {
    let buffer = bincode::serialize(&request).context("encode request")?;
    socket
        .write_u32(buffer.len() as _)
        .await
        .context("write request length")?;
    socket.write_all(&buffer).await.context("write request")?;
    let size = socket.read_u32().await.context("read response length")?;
    let mut buffer = vec![0u8; size as _];
    socket
        .read_exact(&mut buffer)
        .await
        .context("read response")?;
    let response: ControlResponse = bincode::deserialize(&buffer).context("decode response")?;
    Ok(response)
}

/// Draw the UI.
fn draw_ui<B>(f: &mut Frame<B>, state: &State)
where
    B: Backend,
{
    let vertical_panes = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(f.size());
    let top_panes = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(vertical_panes[0]);
    let info_panes = Layout::default()
        .direction(Direction::Vertical)
        .margin(0)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(top_panes[1]);

    let plot_block = Block::default().title("PLOT").borders(Borders::ALL);
    let plot = Canvas::default()
        // .marker(Marker::Block)
        .block(plot_block)
        .x_bounds([-30.0, 30.0])
        .y_bounds([-30.0, 30.0])
        .paint(|c| {
            c.draw(&Points {
                coords: RAD_PTS_LOW,
                color: Color::Gray,
            });
            c.draw(&Points {
                coords: RAD_PTS_MED,
                color: Color::LightYellow,
            });
            c.draw(&Points {
                coords: RAD_PTS_HIGH,
                color: Color::LightRed,
            });
            c.layer();
            c.print(0.0, 0.0, "♁", Color::LightBlue);
            c.print(
                state.position.0 / 1000.0,
                state.position.1 / 1000.0,
                "🛰",
                Color::Green,
            );
        });

    let info_block = Block::default().title("TELEMETRY").borders(Borders::ALL);
    let mut info_text = vec![
        Spans::from(Span::styled(
            "Coordinates (km)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!(
            "  {:6.4}  {:6.4}  {:6.4}",
            state.position.0, state.position.1, state.position.2
        ))),
        Spans::from(Span::styled(
            "Velocity (km/s)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!(
            "  {:6.4}  {:6.4}  {:6.4}",
            state.velocity.0, state.velocity.1, state.velocity.2
        ))),
        Spans::from(Span::styled(
            "Fuel Mass (kg)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!("  {:.4}", state.fuel))),
        Spans::from(Span::styled(
            "Firmware Restarts",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!("  {}", state.restarts))),
        Spans::from(Span::styled(
            "Memory Repairs",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!("  {}", state.repairs))),
        Spans::from(Span::styled(
            "Radiation Level",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Spans::from(Span::raw(format!(
            "  {}",
            if let Some(r) = state.radiation.back() {
                *r
            } else {
                0.0
            }
        ))),
        Spans::from(Span::styled(
            "Modules",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    for (i, m) in state.modules.iter().enumerate() {
        info_text.push(Spans::from(Span::raw(format!(
            "  {:02}: en={} vf={} chk={:016x}",
            i, m.enabled, m.verified, m.checksum
        ))));
    }
    let info = Paragraph::new(info_text).block(info_block);

    let rad_block = Block::default().title("RADIATION").borders(Borders::ALL);
    let rad_levels: Vec<_> = state
        .radiation
        .iter()
        .enumerate()
        .map(|(x, y)| (x as f64, *y))
        .collect();
    let rad_data = vec![Dataset::default()
        .name("radiation")
        .marker(Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Magenta))
        .data(&rad_levels[..])];
    let rad_graph = Chart::new(rad_data)
        .block(rad_block)
        .x_axis(
            Axis::default()
                .bounds([0.0, MAX_RADIATION_POINTS as f64])
                .style(Style::default().fg(Color::White)),
        )
        .y_axis(
            Axis::default()
                .bounds([0.0, 500.0])
                .labels(
                    ["  0", "250", "500"]
                        .iter()
                        .cloned()
                        .map(|x| Span::styled(x, Style::default().add_modifier(Modifier::DIM)))
                        .collect(),
                )
                .style(Style::default().add_modifier(Modifier::DIM)),
        );

    let log_block = Block::default().title("LOG").borders(Borders::ALL);
    let log_text: Vec<_> = state
        .log
        .iter()
        .map(|(t, m)| {
            Spans::from(vec![
                Span::styled(
                    format!("{}: ", t),
                    Style::default().add_modifier(Modifier::DIM),
                ),
                Span::raw(m.to_string()),
            ])
        })
        .collect();
    let mut log_scroll = (0u16, 0u16);
    let log_height = vertical_panes[1].height - 2;
    let num_log_entries = state.log.len() as u16;
    if log_height < num_log_entries {
        log_scroll = (num_log_entries - log_height, 0);
    }
    let log = Paragraph::new(log_text).block(log_block).scroll(log_scroll);

    f.render_widget(plot, top_panes[0]);
    f.render_widget(info, info_panes[0]);
    f.render_widget(rad_graph, info_panes[1]);
    f.render_widget(log, vertical_panes[1]);
}
