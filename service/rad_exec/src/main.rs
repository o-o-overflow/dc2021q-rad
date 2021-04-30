//! Rad executive.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate nyx_space as nyx;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::prelude::*;
use nyx::celestia::bodies::{EARTH_MOON, SUN};
use nyx::celestia::{Cosm, State};
use nyx::dimensions::Vector3;
use nyx::dynamics::orbital::OrbitalDynamics;
use nyx::dynamics::propulsion::{Propulsion, Thruster};
use nyx::dynamics::spacecraft::{Spacecraft, SpacecraftState};
use nyx::dynamics::thrustctrl::{FiniteBurns, Mnvr};
use nyx::propagators::{CashKarp45, PropOpts, Propagator, RSSStepPV};
use nyx::time::Epoch;
use rad_message::{compute_radiation, Burn};
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

mod control;
mod monitor;
mod service;

const FIRMWARE_PATH: &str = "./rad_fw";
const CONTROL_PORT: u16 = 1337;
const MIN_ALTITUDE: f64 = 50.0;
const MAX_ALTITUDE: f64 = 300000.0;
const REPORT_INTERVAL: i64 = 5;
const DRY_MASS: f64 = 100.0;
const FUEL_MASS: f64 = 20.0;

lazy_static! {
    static ref STATE: Arc<Mutex<Option<SpacecraftState>>> = Arc::new(Mutex::new(None));
    static ref BURNS: Arc<Mutex<Option<Vec<Burn>>>> = Arc::new(Mutex::new(None));
    static ref RAD: Mutex<f64> = Mutex::new(0.0);
}

pub type RadCraft<'a> = Propagator<'a, Spacecraft<'a, OrbitalDynamics<'a>>, RSSStepPV>;

/// Main.
#[tokio::main]
async fn main() {
    env_logger::init();

    let (tx_command_requests, mut rx_command_requests) = channel(256);
    let (tx_command_responses, mut rx_command_responses) = channel(256);

    tokio::spawn({
        async move {
            loop {
                if let Err(e) = service::process_connections().await {
                    error!("service firmware: {}", e);
                }
            }
        }
    });

    tokio::spawn(async move {
        loop {
            if let Err(e) =
                control::process_connections(&tx_command_requests, &mut rx_command_responses).await
            {
                error!("service control: {}", e);
            }
        }
    });

    tokio::spawn(async move {
        loop {
            if let Err(e) =
                control::proxy_requests_to_firmware(&mut rx_command_requests, &tx_command_responses)
                    .await
            {
                error!("proxy control: {}", e);
            }
        }
    });

    tokio::spawn(async move {
        loop {
            if let Err(e) = monitor::execute_firmware().await {
                error!("execute firmware: {}", e);
            }
        }
    });

    let mut orbit = None;
    let mut dry_mass = DRY_MASS;
    let mut fuel_mass = FUEL_MASS;
    let mut burns = vec![];

    loop {
        match simulate_spacecraft(orbit, dry_mass, fuel_mass, burns).await {
            Ok((o, d, f, b)) => {
                orbit = Some(o);
                dry_mass = d;
                fuel_mass = f;
                burns = b;
            }
            Err(e) => {
                error!("simulate spacecraft: {}", e);
                break;
            }
        }
    }
}

/// Run the simulation.
async fn simulate_spacecraft(
    orbit: Option<State>,
    dry_mass: f64,
    fuel_mass: f64,
    burns: Vec<Burn>,
) -> Result<(State, f64, f64, Vec<Burn>)> {
    info!(
        "simulating spacecraft dry_mass={} fuel_mass={}",
        dry_mass, fuel_mass
    );
    if let Some(orbit) = orbit {
        info!("initial orbit: {}", orbit);
    }
    info!("burn schedule: {:#?}", burns);

    let ts_start = Utc::now();
    let point_masses = vec![EARTH_MOON, SUN];
    let dt = Epoch::from_gregorian_utc(
        ts_start.year(),
        ts_start.month() as _,
        ts_start.day() as _,
        ts_start.hour() as _,
        ts_start.minute() as _,
        ts_start.second() as _,
        ts_start.nanosecond(),
    );
    let cosm = Cosm::from_xb("data/de438s");
    let eme2k = cosm.frame("EME2000");

    let orbit = orbit.unwrap_or_else(|| {
        // High radiation orbit
        // State::from_geodesic(0.0, 0.0, 4000.0, dt, eme2k)
        // State::from_geodesic(0.0, 0.0, 6000.0, dt, eme2k)

        // Potential start orbit above (but not too far from) inner belt
        State::from_geodesic(42.3601, 71.0589, 16384.0, dt, eme2k)

        // High earth orbit (IBEX)
        // State::keplerian(
        //     202_811.0, 0.6586277, 26.0179, 93.9503, 22.5731, 356.6008, dt, eme2k,
        // )
    });

    // Orbital dynamics
    let dynamics = OrbitalDynamics::point_masses(orbit, point_masses, &cosm);

    // Thrusters and finite burn schedule
    let thrusters = vec![Thruster {
        thrust: 1000.0,
        isp: 300.0,
    }];
    let schedule = FiniteBurns::from_mnvrs(
        burns
            .into_iter()
            .map(|b| {
                let start = Epoch::from_tai_seconds(b.start as _);
                Mnvr {
                    start,
                    end: start + b.length as f64,
                    thrust_lvl: b.thrust,
                    vector: Vector3::new(b.vector.0, b.vector.1, b.vector.2),
                }
            })
            .collect(),
    );
    let prop_subsys = Propulsion::new(Box::new(schedule), thrusters.clone(), true);

    // Spacecraft
    let mut craft = Spacecraft::with_prop(dynamics, prop_subsys, dry_mass, fuel_mass);

    // Propagator
    let prop_opts = PropOpts::default();
    let mut prop = Propagator::new::<CashKarp45>(&mut craft, &prop_opts);

    let mut ts_last = ts_start;
    let mut ts_last_report = ts_start;
    loop {
        let ts_now = Utc::now();

        // Update the spacecraft's state
        let current_state =
            prop.until_time_elapsed((ts_now.timestamp() - ts_last.timestamp()) as f64);
        *STATE.lock().map_err(|_| anyhow!("state lock"))? = Some(current_state);
        *RAD.lock().map_err(|_| anyhow!("flux lock"))? = compute_radiation(
            current_state.orbit.geodetic_latitude(),
            current_state.orbit.geodetic_height(),
        );

        // Check if we should report current position
        if (ts_now - ts_last_report).num_seconds() > REPORT_INTERVAL {
            info!("{}", current_state);
            info!(
                "lat={} lon={} alt={} flux={}",
                current_state.orbit.geodetic_latitude(),
                current_state.orbit.geodetic_longitude(),
                current_state.orbit.geodetic_height(),
                *RAD.lock().map_err(|_| anyhow!("flux lock"))?,
            );
            ts_last_report = ts_now;
        }

        // Check if a physical failure condition has occurred
        let altitude = current_state.orbit.geodetic_height();
        if altitude < MIN_ALTITUDE {
            return Err(anyhow!("BOOM (altitude {} km)", altitude));
        } else if altitude > MAX_ALTITUDE {
            return Err(anyhow!("LOST CONTACT (altitude {} km)", altitude));
        }
        if prop.dynamics.fuel_mass <= 0.0 {
            return Err(anyhow!("FUEL EXHAUSTED"));
        }

        // Check if we need to update the craft's orbital maneuvers
        if let Some(burns) = BURNS.lock().map_err(|_| anyhow!("burns lock"))?.take() {
            return Ok((
                current_state.orbit,
                current_state.dry_mass,
                current_state.fuel_mass,
                burns,
            ));
        }

        ts_last = ts_now;
        sleep(Duration::from_millis(100)).await;
    }
}
