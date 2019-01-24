# FCM/APNs Push Relay

[![CircleCI][circle-ci-badge]][circle-ci]
[![License][license-badge]][license]

This server accepts push requests via HTTP and notifies the Google FCM / Apple
APNs push services.

## Request Format

- POST request to `/push`
- Request body must use `application/x-www-form-urlencoded` encoding

Request keys:

- `type`: Either `fcm` or `apns`
- `token`: The device push token
- `session`: SHA256 hash of public permanent key of the initiator
- `version`: Threema Web protocol version
- `bundleid` (APNs only): The bundle id to use
- `endpoint` (APNs only): Either `p` (production) or `s` (sandbox)

Examples:

    curl -X POST -H "Origin: https://localhost" localhost:3000/push \
        -d "type=fcm&token=asdf&session=123deadbeef&version=3"
    curl -X POST -H "Origin: https://localhost" localhost:3000/push \
        -d "type=apns&token=asdf&session=123deadbeef&version=3&bundleid=com.example.app&endpoint=s"

Possible response codes:

- `HTTP 204 (No Content)`: Request was processed successfully
- `HTTP 400 (Bad Request)`: Invalid or missing POST parameters (including expired push tokens)
- `HTTP 502 (Bad Gateway)`: Processing of push request failed

## Push Payload

The payload format looks like this:

- `wcs`: Webclient session (sha256 hash of the public permanent key of the
  initiator), `string`
- `wct`: Unix epoch timestamp of the request in seconds, `i64`
- `wcv`: Protocol version, `u16`

### FCM

The FCM message contains the payload data as specified above.

The TTL of the message is currently hardcoded to 90 seconds.

### APNs

The APNs message contains a key "3mw" containing the payload data as specified
above.

## Running

You need the Rust compiler (1.31 or higher). First, create a `config.ini` file
that looks like this:

    [fcm]
    api_key = "your-api-key"

    [apns]
    keyfile = "your-keyfile.p8"
    key_id = "AB123456XY"
    team_id = "CD987654YZ"

If you want to log the pushes to InfluxDB, add the following section:

    [influxdb]
    connection_string = "http://127.0.0.1:8086"
    user = "foo"
    pass = "bar"
    db = "baz"

Then simply run

    export RUST_LOG=push_relay=debug,hyper=info,a2=info
    cargo run

...to build and start the server in debug mode.

## Deployment

- Always create a build in release mode: `cargo build --release`
- Use a reverse proxy with proper TLS termination (e.g. Nginx)
- Set `RUST_LOG=push_relay=info,hyper=info,a2=info` env variable

## Testing

To run tests:

    cargo test

## Linting

To run lints:

    $ rustup component add clippy
    $ cargo clean && cargo clippy --all-targets

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

<!-- Badges -->
[circle-ci]: https://circleci.com/gh/threema-ch/push-relay/tree/master
[circle-ci-badge]: https://circleci.com/gh/threema-ch/push-relay/tree/master.svg?style=shield
[license]: https://github.com/threema-ch/push-relay#license
[license-badge]: https://img.shields.io/badge/License-Apache%202.0%20%2f%20MIT-blue.svg
