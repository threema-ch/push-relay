//! Configuration.

use std::{collections::HashMap, fs::File, io::Read, path::Path};

use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub fcm: FcmConfig,
    pub apns: ApnsConfig,
    pub hms: Option<HashMap<String, HmsConfig>>,
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
        Ok(toml::from_str(&contents).map_err(|e| e.to_string())?)
    }
}
