//! # GCM Push Relay
//!
//! This server accepts push requests via HTTPS and notifies the GCM push
//! service.

extern crate a2;
extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate futures;
extern crate http;
extern crate hyper;
extern crate hyper_tls;
extern crate ini;
#[macro_use]
extern crate log;
extern crate mime;
#[macro_use]
extern crate quick_error;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate url;

#[cfg(test)]
extern crate mockito;

#[macro_use]
mod utils;
mod errors;
mod push;
mod server;

use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::process;

use clap::{App, Arg};
use ini::Ini;

const NAME: &'static str = "push-relay";
const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const DESCRIPTION: &'static str =
    "This server accepts push requests via HTTP and notifies the GCM push service.";

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

    // Determine GCM API key
    let config_gcm = config.section(Some("gcm".to_owned())).unwrap_or_else(|| {
        error!("Invalid config file: No [gcm] section in {}", configfile);
        process::exit(2);
    });
    let gcm_api_key = config_gcm.get("api_key").unwrap_or_else(|| {
        error!(
            "Invalid config file: No 'api_key' key in [gcm] section in {}",
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
    server::serve(gcm_api_key, apns_api_key, apns_team_id, apns_key_id, addr).unwrap_or_else(
        |e| {
            error!("Could not start relay server: {}", e);
            process::exit(3);
        },
    );
}
