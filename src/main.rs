//! # FCM Push Relay
//! 
//! This server accepts push requests via HTTPS and notifies the FCM push
//! service.

extern crate hyper;
extern crate iron;
extern crate router;

mod server;

fn main() {
    let listen = "localhost:3000";
    println!("Starting Push Relay Server on {}", &listen);
    server::serve(listen);
}
