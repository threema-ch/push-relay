# GCM Push Relay

This server accepts push requests via HTTP and notifies the GCM push service.

## Request Format

- POST request to `/push`
- Request body must use `application/x-www-form-urlencoded` encoding
- The keys `token` (GCM token) and `session` (public permanent key of the initiator) must be present

Example:

    curl -X POST [::1]:3000/push -d "token=asdf&session=123deadbeef"

Possible response codes:

- `HTTP 204 (No Content)`: Request was processed successfully
- `HTTP 400 (Bad Request)`: Invalid or missing POST parameters
- `HTTP 500 (Internal Server Error)`: Processing of push request failed

## GCM Message Format

The GCM message contains the following two data keys:

- `wcs`: Webclient session (public permanent key of the initiator)
- `wtc`: Unix epoch timestamp of the request

It is sent with a TTL of 5 minutes.

## Running

You need the Rust compiler (1.11+). First, create a `config.ini` file that
looks like this:

    [gcm]
    api_key = "your-api-key"

Then simply run

    cargo run

...to build and start the server in debug mode.

## Logging

To see debug logging:

    export RUST_LOG=push_relay=debug

## Deployment

- Always create a build in release mode: `cargo build --release`
- Use a reverse proxy with proper TLS termination (e.g. Nginx)
- Set `RUST_LOG=push_relay=info` env variable
