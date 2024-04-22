//! Configuration.

use std::{collections::HashMap, fs::File, io::Read, path::Path};

use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub fcm: FcmConfig,
    pub apns: ApnsConfig,
    pub hms: Option<HashMap<String, HmsConfig>>,
    pub threema_gateway: Option<ThreemaGatewayConfig>,
    pub influxdb: Option<InfluxdbConfig>,
}

#[derive(Debug, Deserialize)]
pub struct FcmConfig {
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ApnsConfig {
    pub keyfile: String,
    pub key_id: String,
    pub team_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HmsConfig {
    pub client_id: String,
    pub client_secret: String,
    pub high_priority: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ThreemaGatewayConfig {
    pub base_url: String,
    pub identity: String,
    pub secret: String,
    pub private_key_file: String,
}

#[derive(Debug, Deserialize)]
pub struct InfluxdbConfig {
    pub connection_string: String,
    pub user: String,
    pub pass: String,
    pub db: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| e.to_string())?;
        toml::from_str(&contents).map_err(|e| e.to_string())
    }
}
