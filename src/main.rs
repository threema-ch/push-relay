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
extern crate log;

mod config;
mod errors;
mod http_client;
mod influxdb;
mod push;
mod server;

use std::{fs::File, io::Read, net::SocketAddr, path::PathBuf, process};

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
async fn main() {
    env_logger::init();

    let args = Args::parse();

    // Load config file
    let config = Config::load(&args.config).unwrap_or_else(|e| {
        error!("Could not load config file {:?}: {}", args.config, e);
        process::exit(2);
    });

    // Determine HMS credentials
    info!("Found FCM config");
    info!("Found APNs config");
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
    let threema_gateway_private_key = match config.threema_gateway {
        None => {
            warn!(
                "No Threema Gateway credentials found in config, Threema pushes cannot be handled"
            );
            None
        }
        Some(ref threema_gateway_config) => {
            info!(
                "Found Threema Gateway config: {}",
                &threema_gateway_config.identity
            );

            // Open and read private key
            let mut private_key = Zeroizing::new(Vec::new());
            File::open(&threema_gateway_config.private_key_file)
                .unwrap_or_else(|e| {
                    error!(
                        "Invalid Threema Gateway 'private_key_file' path: Could not open '{}': {}",
                        threema_gateway_config.private_key_file, e
                    );
                    process::exit(3);
                })
                .read_to_end(&mut private_key)
                .unwrap_or_else(|e| {
                    error!(
                        "Invalid Threema Gateway 'private_key_file': Could not read '{}': {}",
                        threema_gateway_config.private_key_file, e
                    );
                    process::exit(3);
                });

            // Strip `private:` prefix and new-line suffix
            let private_key = private_key.strip_prefix(b"private:").unwrap_or_else(|| {
                error!(
                    "Invalid Threema Gateway 'private_key_file': Private key not prefixed with 'private:'",
                );
                process::exit(3);
            });
            let private_key = private_key.strip_suffix(b"\n").unwrap_or(private_key);

            // Decode private key
            let private_key = Zeroizing::new(HEXLOWER_PERMISSIVE
                    .decode(private_key)
                    .unwrap_or_else(|e| {
                        error!(
                            "Invalid Threema Gateway 'private_key_file': Could not hex decode private key: {}",
                            e
                        );
                        process::exit(3);
                    }));
            let private_key_length = private_key.len();
            let private_key = ThreemaGatewayPrivateKey(<[u8; 32]>::try_from(private_key.as_ref()).unwrap_or_else(|_| {
                error!(
                    "Invalid Threema Gateway 'private_key_file': Could not decode private key, invalid length: {}",
                    private_key_length
                );
                process::exit(3);
            }));
            Some(private_key)
        }
    };

    // Open and read APNs keyfile
    let mut apns_keyfile = File::open(&config.apns.keyfile).unwrap_or_else(|e| {
        error!(
            "Invalid APNs 'keyfile' path: Could not open '{}': {}",
            config.apns.keyfile, e
        );
        process::exit(3);
    });
    let mut apns_api_key = Vec::new();
    apns_keyfile
        .read_to_end(&mut apns_api_key)
        .unwrap_or_else(|e| {
            error!(
                "Invalid 'keyfile': Could not read '{}': {}",
                config.apns.keyfile, e
            );
            process::exit(3);
        });

    info!("Starting Push Relay Server {} on {}", VERSION, &args.listen);

    if let Err(e) = server::serve(
        config,
        &apns_api_key,
        threema_gateway_private_key,
        args.listen,
    )
    .await
    {
        error!("Server error: {}", e);
        process::exit(3);
    }
}
