//! # FCM/APNs Push Relay
//!
//! This server accepts push requests via HTTPS and notifies the FCM push
//! service.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_unwrap_or)]
#![allow(clippy::map_err_ignore)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::non_ascii_literal)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

#[macro_use]
extern crate log;

#[macro_use]
mod utils;
mod config;
mod errors;
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

fn main() {
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
    server::serve(config, &apns_api_key, addr).unwrap_or_else(|e| {
        error!("Could not start relay server: {}", e);
        process::exit(3);
    });
}
