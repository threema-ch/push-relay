//! # FCM/APNs/HMS Push Relay
//!
//! This server accepts push requests via HTTPS and notifies the push
//! service.
//!
//! Supported service:
//!
//! - Google FCM
//! - Apple APNs
//! - Huawei HMS

#![deny(clippy::all)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_unwrap_or)]

#[macro_use]
extern crate tracing;

mod config;
mod errors;
mod http_client;
mod influxdb;
mod push;
mod server;

use std::{fs::File, io::Read, net::SocketAddr, path::PathBuf};

use anyhow::{Context as _, anyhow};
use clap::Parser;
use data_encoding::HEXLOWER_PERMISSIVE;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, ZeroizeOnDrop)]
pub struct ThreemaGatewayPrivateKey([u8; 32]);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The ip/port to listen on
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,

    /// Path to a config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::try_init()
        .map_err(|e| anyhow!("Could not init tracing_subscriber: {e}"))?;

    let args = Args::parse();

    // Load config file
    let config = Config::load(&args.config)
        .map_err(|e| anyhow!("Could not load config file {:?}: {}", args.config, e))?;

    // Determine HMS credentials
    match config.hms {
        None => {
            warn!("No HMS credentials found in config, HMS pushes cannot be handled");
        }
        Some(ref map) if map.is_empty() => {
            warn!("No HMS credentials found in config, HMS pushes cannot be handled");
        }
        Some(ref map) => {
            let keys = map.keys().collect::<Vec<_>>();
            info!("Found {} HMS config(s): {:?}", map.len(), keys);
        }
    }

    // Determine Threema Gateway credentials
    let threema_gateway_private_key = get_gateway_key(&config)?;

    let apns_api_key =
        if let Some(apns_key_path) = config.apns.as_ref().map(|apns_config| &apns_config.keyfile) {
            info!("Found APNs config");

            Some(std::fs::read(apns_key_path).context(format!(
                "Invalid 'keyfile': Could not read '{}'",
                apns_key_path
            ))?)
        } else {
            None
        };

    info!("Starting Push Relay Server {} on {}", VERSION, &args.listen);

    server::serve(
        config,
        apns_api_key,
        threema_gateway_private_key,
        args.listen,
    )
    .await
    .context("Failed to serve app")
}

fn get_gateway_key(config: &Config) -> anyhow::Result<Option<ThreemaGatewayPrivateKey>> {
    match config.threema_gateway {
        None => {
            warn!(
                "No Threema Gateway credentials found in config, Threema pushes cannot be handled"
            );
            Ok(None)
        }
        Some(ref threema_gateway_config) => {
            info!(
                "Found Threema Gateway config: {}",
                &threema_gateway_config.identity
            );

            // Open and read private key
            let mut private_key = Zeroizing::new(Vec::new());
            File::open(&threema_gateway_config.private_key_file)
                .map_err(|e| {
                    anyhow!(
                        "Invalid Threema Gateway 'private_key_file' path: Could not open '{}': {}",
                        threema_gateway_config.private_key_file,
                        e
                    )
                })?
                .read_to_end(&mut private_key)
                .map_err(|e| {
                    anyhow!(
                        "Invalid Threema Gateway 'private_key_file': Could not read '{}': {}",
                        threema_gateway_config.private_key_file,
                        e
                    )
                })?;

            // Strip `private:` prefix and new-line suffix
            let private_key = private_key.strip_prefix(b"private:").ok_or_else(|| {
                anyhow!(
                    "Invalid Threema Gateway 'private_key_file': Private key not prefixed with 'private:'",
                )
            })?;
            let private_key = private_key.strip_suffix(b"\n").unwrap_or(private_key);

            // Decode private key
            let private_key = Zeroizing::new(HEXLOWER_PERMISSIVE.decode(private_key).context(
                "Invalid Threema Gateway 'private_key_file': Could not hex decode private key",
            )?);
            let private_key_length = private_key.len();
            let private_key = ThreemaGatewayPrivateKey(<[u8; 32]>::try_from(private_key.as_ref()).map_err(|_| {
                anyhow!(
                    "Invalid Threema Gateway 'private_key_file': Could not decode private key, invalid length: {}",
                    private_key_length
                )
            })?);
            Ok(Some(private_key))
        }
    }
}
