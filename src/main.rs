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

use std::{fs::File, io::Read, net::SocketAddr, path::Path, process};

use clap::{App, Arg};

use config::Config;

const NAME: &str = "push-relay";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &str =
    "This server accepts push requests via HTTP and notifies FCM/APNs push services.";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    env_logger::init();

    let matches = App::new(NAME)
        .version(VERSION)
        .about(DESCRIPTION)
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .value_name("host:port")
                .help("The ip/port to listen on. Default: 127.0.0.1:3000."),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("path")
                .help("Path to a configfile. Default: config.toml."),
        )
        .get_matches();

    let listen = matches.value_of("listen").unwrap_or("127.0.0.1:3000");
    let addr: SocketAddr = listen.parse().unwrap_or_else(|e| {
        error!("Invalid listen address: {} ({})", listen, e);
        process::exit(1);
    });

    let configfile = matches.value_of("config").unwrap_or("config.toml");

    // Load config file
    let config = Config::load(Path::new(configfile)).unwrap_or_else(|e| {
        error!("Could not load config file '{}': {}", configfile, e);
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

    info!("Starting Push Relay Server {} on {}", VERSION, &addr);

    if let Err(e) = server::serve(config, &apns_api_key, addr).await {
        error!("Server error: {}", e);
        process::exit(3);
    }
}
