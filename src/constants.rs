pub const DEFAULT_SCAN_TIMEOUT_MS: u64 = 1000;

pub const MAX_CONCURRENT_CONNS: usize = 200;

pub const DEFAULT_EXPLOIT_TIMEOUT_SECS: u64 = 10;

pub const NMAP_TIMEOUT_SECS: u64 = 30;

pub const NMAP_VERSION_INTENSITY: u8 = 1;

pub const PROGRESS_UPDATE_INTERVAL_MS: u64 = 100;

pub const MAX_DISPLAYED_EXPLOITS: usize = 10;

pub mod risk {
    pub const CRITICAL: f32 = 50.0;
    pub const HIGH: f32 = 30.0;
    pub const MEDIUM: f32 = 15.0;
}

pub mod service_multipliers {
    pub const SMB: f32 = 1.8;
    pub const DATABASE: f32 = 1.6;
    pub const REMOTE_ACCESS: f32 = 1.5;
    pub const WEB: f32 = 1.3;
    pub const DEFAULT: f32 = 1.0;
}
pub mod ports {
    pub const MAX: u16 = 65535;
    pub const MIN: u16 = 1;
    pub const DEFAULT_LIMIT: u16 = 1000;
    pub const MAX_K_VALUE: u16 = 30;
}

pub mod progress {
    pub const DEFAULT_WIDTH: usize = 40;
}

pub mod validation {
    pub const MAX_TARGET_LENGTH: usize = 253;
}
