//! # FCM/APNs Push Relay
//!
//! This server accepts push requests via HTTPS and notifies the FCM push
//! service.

#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::non_ascii_literal)]
#![allow(clippy::match_same_arms)]

#[macro_use]
extern crate log;

use env_logger;

#[macro_use]
mod utils;
mod errors;
mod influxdb;
mod push;
mod server;

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::process;

use clap::{App, Arg};
use ini::Ini;

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
                .help("Path to a configfile. Default: config.ini."),
        )
        .get_matches();

    let listen = matches.value_of("listen").unwrap_or("127.0.0.1:3000");
    let addr: SocketAddr = listen.parse().unwrap_or_else(|e| {
        error!("Invalid listen address: {} ({})", listen, e);
        process::exit(1);
    });

    let configfile = matches.value_of("config").unwrap_or("config.ini");

    // Load config file
    let config = Ini::load_from_file(configfile).unwrap_or_else(|e| {
        error!("Could not open config file: {}", e);
        process::exit(1);
    });

    // Determine FCM API key
    let config_fcm = config.section(Some("fcm".to_owned())).unwrap_or_else(|| {
        error!("Invalid config file: No [fcm] section in {}", configfile);
        process::exit(2);
    });
    let fcm_api_key = config_fcm.get("api_key").unwrap_or_else(|| {
        error!(
            "Invalid config file: No 'api_key' key in [fcm] section in {}",
            configfile
        );
        process::exit(2);
    });

    // Determine APNs config
    let config_apns = config.section(Some("apns".to_owned())).unwrap_or_else(|| {
        error!("Invalid config file: No [apns] section in {}", configfile);
        process::exit(2);
    });
    let apns_keyfile_path = config_apns.get("keyfile").unwrap_or_else(|| {
        error!(
            "Invalid config file: No 'keyfile' key in [apns] section in {}",
            configfile
        );
        process::exit(2);
    });
    let apns_team_id = config_apns.get("team_id").unwrap_or_else(|| {
        error!(
            "Invalid config file: No 'team_id' key in [apns] section in {}",
            configfile
        );
        process::exit(2);
    });
    let apns_key_id = config_apns.get("key_id").unwrap_or_else(|| {
        error!(
            "Invalid config file: No 'key_id' key in [apns] section in {}",
            configfile
        );
        process::exit(2);
    });

    // Determine InfluxDB config
    let influxdb = config.section(Some("influxdb".to_owned())).map(|c| {
        influxdb::Influxdb::init(
            c.get("connection_string").unwrap_or_else(|| {
                error!("Invalid config file: No 'connection_string' key in [influxdb] secttion in {}", configfile);
                process::exit(3);
            }).to_owned(),
            c.get("user").unwrap_or_else(|| {
                error!("Invalid config file: No 'user' key in [influxdb] secttion in {}", configfile);
                process::exit(3);
            }),
            c.get("pass").unwrap_or_else(|| {
                error!("Invalid config file: No 'pass' key in [influxdb] secttion in {}", configfile);
                process::exit(3);
            }),
            c.get("db").unwrap_or_else(|| {
                error!("Invalid config file: No 'db' key in [influxdb] secttion in {}", configfile);
                process::exit(3);
            }).to_owned(),
        ).expect("Failed to create Influxdb instance")
    });

    // Open APNs keyfile
    let mut apns_keyfile = File::open(apns_keyfile_path).unwrap_or_else(|e| {
        error!(
            "Invalid 'keyfile' path: Could not open '{}': {}",
            apns_keyfile_path, e
        );
        process::exit(3);
    });
    let mut apns_api_key = Vec::new();
    apns_keyfile
        .read_to_end(&mut apns_api_key)
        .unwrap_or_else(|e| {
            error!(
                "Invalid 'keyfile': Could not read '{}': {}",
                apns_keyfile_path, e
            );
            process::exit(3);
        });

    info!("Starting Push Relay Server {} on {}", VERSION, &addr);
    server::serve(
        fcm_api_key,
        &apns_api_key,
        apns_team_id,
        apns_key_id,
        addr,
        influxdb,
    ).unwrap_or_else(
        |e| {
            error!("Could not start relay server: {}", e);
            process::exit(3);
        },
    );
}
