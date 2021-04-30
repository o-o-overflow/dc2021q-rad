//! Rad messages.

use serde::{Deserialize, Serialize};

pub const CHECKPOINT_PATH: &str = "./rad.chkpt";
pub const SERVICE_PATH: &str = "./rad_exec_svc.socket";
pub const COMMAND_PATH: &str = "./rad_exec_cmd.socket";
pub const MAX_MESSAGE_SIZE: usize = 256;

/// Ground control request.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ControlRequest {
    NoOp,
    Authenticate {
        token: Vec<u8>,
        nonce: Vec<u8>,
    },
    Reset,
    Firmware,
    PositionVelocity,
    KeplerianElements,
    Sensors,
    EnableModule {
        id: u8,
        enable: bool,
    },
    UpdateModule {
        id: u8,
        module: Vec<u8>,
        signature: Vec<u8>,
        encoded: bool,
    },
    Maneuver {
        burns: Vec<Burn>,
    },
    Disconnect,
}

impl ControlRequest {
    /// Return a failure response.
    pub fn to_failure(&self) -> ControlResponse {
        use self::*;
        match *self {
            ControlRequest::NoOp => ControlResponse::NoOp,
            ControlRequest::Authenticate { .. } => ControlResponse::Authenticate {
                authenticated: false,
                connected: false,
            },
            ControlRequest::Reset => ControlResponse::Reset { success: false },
            ControlRequest::Firmware => ControlResponse::Firmware {
                success: false,
                repairs: 0,
                restarts: 0,
                events: vec![],
                modules: vec![],
            },
            ControlRequest::PositionVelocity => ControlResponse::PositionVelocity {
                success: false,
                t: 0,
                p: (0.0, 0.0, 0.0),
                v: (0.0, 0.0, 0.0),
            },
            ControlRequest::KeplerianElements => ControlResponse::KeplerianElements {
                success: false,
                dt: 0,
                sma: 0.0,
                ecc: 0.0,
                inc: 0.0,
                raan: 0.0,
                aop: 0.0,
                ta: 0.0,
            },
            ControlRequest::Sensors => ControlResponse::Sensors {
                success: false,
                fuel: 0.0,
                radiation: 0.0,
            },
            ControlRequest::EnableModule { .. } => ControlResponse::EnableModule { success: false },
            ControlRequest::UpdateModule { .. } => ControlResponse::EnableModule { success: false },
            ControlRequest::Maneuver { .. } => ControlResponse::Maneuver { success: false },
            ControlRequest::Disconnect => ControlResponse::Disconnect,
        }
    }
}

impl std::fmt::Display for ControlRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ControlRequest::*;
        match *self {
            NoOp => write!(f, "NoOp"),
            Authenticate { .. } => write!(f, "Authenticate"),
            Reset => write!(f, "Reset"),
            Firmware => write!(f, "Firmware"),
            PositionVelocity => write!(f, "PositionVelocity"),
            KeplerianElements => write!(f, "KeplerianElements"),
            Sensors => write!(f, "Sensors"),
            EnableModule { .. } => write!(f, "EnableModule"),
            UpdateModule { .. } => write!(f, "UpdateModule"),
            Maneuver { .. } => write!(f, "Maneuver"),
            Disconnect => write!(f, "Disconnect"),
        }
    }
}

/// Ground control response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ControlResponse {
    NoOp,
    Authenticate {
        authenticated: bool,
        connected: bool,
    },
    Reset {
        success: bool,
    },
    Firmware {
        success: bool,
        repairs: u64,
        restarts: u64,
        events: Vec<Event>,
        modules: Vec<ModuleStatus>,
    },
    PositionVelocity {
        success: bool,
        t: u64,
        p: (f64, f64, f64),
        v: (f64, f64, f64),
    },
    KeplerianElements {
        success: bool,
        dt: u64,
        sma: f64,
        ecc: f64,
        inc: f64,
        raan: f64,
        aop: f64,
        ta: f64,
    },
    Sensors {
        success: bool,
        fuel: f64,
        radiation: f64,
    },
    EnableModule {
        success: bool,
    },
    UpdateModule {
        success: bool,
        checksum: u64,
        verified: bool,
        enabled: bool,
    },
    Maneuver {
        success: bool,
    },
    Custom {
        data: Vec<u8>,
    },
    Disconnect,
}

impl std::fmt::Display for ControlResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ControlResponse::*;
        match *self {
            NoOp => write!(f, "NoOp"),
            Authenticate { .. } => write!(f, "Authenticate"),
            Reset { .. } => write!(f, "Reset"),
            Firmware { .. } => write!(f, "Firmware"),
            PositionVelocity { .. } => write!(f, "PositionVelocity"),
            KeplerianElements { .. } => write!(f, "KeplerianElements"),
            Sensors { .. } => write!(f, "Sensors"),
            EnableModule { .. } => write!(f, "EnableModule"),
            UpdateModule { .. } => write!(f, "UpdateModule"),
            Maneuver { .. } => write!(f, "Maneuver"),
            Custom { .. } => write!(f, "Custom"),
            Disconnect => write!(f, "Disconnect"),
        }
    }
}

/// Executive request.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ExecutiveRequest {
    Checkpoint { state: Vec<u8> },
    PositionVelocity,
    KeplerianElements,
    Sensors,
    Maneuver { burns: Vec<Burn> },
}

impl std::fmt::Display for ExecutiveRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ExecutiveRequest::*;
        match *self {
            Checkpoint { .. } => write!(f, "Checkpoint"),
            PositionVelocity => write!(f, "PositionVelocity"),
            KeplerianElements => write!(f, "KeplerianElements"),
            Sensors => write!(f, "Sensors"),
            Maneuver { .. } => write!(f, "Maneuver"),
        }
    }
}

/// Executive response.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum ExecutiveResponse {
    Checkpoint {
        success: bool,
    },
    PositionVelocity {
        success: bool,
        t: u64,
        p: (f64, f64, f64),
        v: (f64, f64, f64),
    },
    KeplerianElements {
        success: bool,
        dt: u64,
        sma: f64,
        ecc: f64,
        inc: f64,
        raan: f64,
        aop: f64,
        ta: f64,
    },
    Sensors {
        success: bool,
        fuel: f64,
        radiation: f64,
    },
    Maneuver {
        success: bool,
    },
}

impl std::fmt::Display for ExecutiveResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ExecutiveResponse::*;
        match *self {
            Checkpoint { .. } => write!(f, "Checkpoint"),
            PositionVelocity { .. } => write!(f, "PositionVelocity"),
            KeplerianElements { .. } => write!(f, "KeplerianElements"),
            Sensors { .. } => write!(f, "Sensors"),
            Maneuver { .. } => write!(f, "Maneuver"),
        }
    }
}

/// Burn.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Burn {
    /// Burn start timestamp (sec)
    pub start: u64,
    /// Burn length (sec)
    pub length: u8,
    /// Thrust level (0-1)
    pub thrust: f64,
    /// Thrust vector (deg)
    pub vector: (f64, f64, f64),
}

/// Event.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: u64,
    pub message: Vec<u8>,
}

impl Event {
    /// Create a new event.
    pub fn new(timestamp: u64, message: Vec<u8>) -> Self {
        Self { timestamp, message }
    }
}

/// Module status.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub enabled: bool,
    pub verified: bool,
    pub checksum: u64,
}

impl ModuleStatus {
    /// Create a new status.
    pub fn new(enabled: bool, verified: bool, checksum: u64) -> Self {
        Self {
            enabled,
            verified,
            checksum,
        }
    }
}

/// Compute radiation strength given a position.
pub fn compute_radiation(latitude: f64, altitude: f64) -> f64 {
    let mut l_level = 0.812625 - 0.000996678 * latitude.powf(2.0) + 0.2;
    if l_level > 1.0 {
        l_level = 1.0;
    } else if l_level < 0.0 {
        l_level = 0.0;
    }

    let mut a_level = if altitude < 4000.0 {
        0.689631 * (0.00164673 * altitude).exp()
    } else if altitude < 8000.0 {
        363028.0 * (-0.00164673 * altitude).exp()
    } else {
        0.0
    };
    if a_level < 0.0 {
        a_level = 0.0;
    }

    l_level * a_level
}
