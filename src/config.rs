//! Configuration.

use std::{collections::HashMap, fs::File, io::Read, path::Path};

use base64::{engine::general_purpose, Engine};
use serde::{de::Error as DeserializeError, Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub fcm: FcmConfig,
    pub apns: ApnsConfig,
    pub hms: Option<HashMap<String, HmsConfig>>,
    pub threema_gateway: Option<ThreemaGatewayConfig>,
    pub influxdb: Option<InfluxdbConfig>,
}

#[derive(Debug, Deserialize)]
pub struct FcmApplicationSecret(#[serde(deserialize_with = "deserialize_base64")] Vec<u8>);

impl AsRef<[u8]> for FcmApplicationSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        general_purpose::STANDARD
            .decode(string)
            .map_err(|err: base64::DecodeError| DeserializeError::custom(err.to_string()))
    })
}

impl<S: Into<Vec<u8>>> From<S> for FcmApplicationSecret {
    fn from(value: S) -> Self {
        let vec = value.into();
        FcmApplicationSecret(vec)
    }
}

#[derive(Debug, Deserialize)]
pub struct FcmConfig {
    #[serde(rename = "service_account_key_base64")]
    pub service_account_key: FcmApplicationSecret,
    pub project_id: String,
    pub max_retries: u8,
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
