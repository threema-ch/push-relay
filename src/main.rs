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

use config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[clap(about, version)]
#[clap(setting = clap::AppSettings::DisableColoredHelp)]
struct Args {
    /// The ip/port to listen on
    #[clap(short, long, default_value = "127.0.0.1:3000")]
    listen: SocketAddr,

    /// Path to a config file
    #[clap(short, long, default_value = "config.toml")]
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

    // Open and read APNs keyfile
    let mut apns_keyfile = File::open(&config.apns.keyfile).unwrap_or_else(|e| {
        error!(
            "Invalid 'keyfile' path: Could not open '{}': {}",
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

    if let Err(e) = server::serve(config, &apns_api_key, args.listen).await {
        error!("Server error: {}", e);
        process::exit(3);
    }
}
