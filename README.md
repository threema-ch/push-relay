# GCM Push Relay

This server accepts push requests via HTTP and notifies the GCM push service.

## Request Format

- POST request to `/push`
- Request body must use `application/x-www-form-urlencoded` encoding
- The keys `token` (GCM token), `session` (public permanent key of the
  initiator) and `version` (webclient protocol version) must be present

Example:

    curl -X POST -H "Origin: https://localhost" localhost:3000/push -d "token=asdf&session=123deadbeef&version=3"

Possible response codes:

- `HTTP 204 (No Content)`: Request was processed successfully
- `HTTP 400 (Bad Request)`: Invalid or missing POST parameters
- `HTTP 500 (Internal Server Error)`: Processing of push request failed

## GCM Message Format

The GCM message contains the following two data keys:

- `wcs`: Webclient session (public permanent key of the initiator), `string`
- `wct`: Unix epoch timestamp of the request, `i64`
- `wcv`: Protocol version, `u16` or `null`

The TTL of the message is currently hardcoded to 45 seconds.

## Running

You need the Rust compiler (current stable). First, create a `config.ini` file
that looks like this:

    [gcm]
    api_key = "your-api-key"

Then simply run

    export RUST_LOG=push_relay=debug
    cargo run

...to build and start the server in debug mode.

## Deployment

- Always create a build in release mode: `cargo build --release`
- Use a reverse proxy with proper TLS termination (e.g. Nginx)
- Set `RUST_LOG=push_relay=info` env variable
