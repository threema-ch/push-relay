# Push Relay

[![CI][ci-badge]][ci]
[![License][license-badge]][license]

This server accepts push requests via HTTP and relays those requests to the appropriate push backends.

Supported backends:

- Google FCM
- Apple APNs
- Huawei HMS

## Request Format

- POST request to `/push`
- Request body must use `application/x-www-form-urlencoded` encoding

Request keys:

- `type`: Either `fcm`, `hms` or `apns`
- `subtype` (HMS only): can be used to differentiate between multiple named configs
- `token`: The device push token
- `session`: SHA256 hash of public permanent key of the initiator
- `version`: Threema Web protocol version
- `affiliation` (optional): An identifier for affiliating consecutive pushes
- `ttl` (optional): The lifespan of a push message, defaults to 90 seconds
- `collapse_key`: (optional) A parameter identifying a group of push messages that can be
  collapsed.
- `bundleid` (APNs only): The bundle id to use
- `endpoint` (APNs only): Either `p` (production) or `s` (sandbox)

Examples:

    curl -X POST -H "Origin: https://localhost" localhost:3000/push \
        -d "type=fcm&token=asdf&session=123deadbeef&version=3"
    curl -X POST -H "Origin: https://localhost" localhost:3000/push \
        -d "type=apns&token=asdf&session=123deadbeef&version=3&bundleid=com.example.app&endpoint=s"
    curl -X POST -H "Origin: https://localhost" localhost:3000/push \
        -d "type=hms&subtype=consumer&token=asdf&session=123deadbeef&version=3"

Possible response codes:

- `HTTP 204 (No Content)`: Request was processed successfully
- `HTTP 400 (Bad Request)`: Invalid or missing POST parameters (including expired push tokens)
- `HTTP 500 (Internal Server Error)`: Processing of push request failed on the Push Relay server
- `HTTP 502 (Bad Gateway)`: Processing of push request failed on the FCM, HMS or APNs server

## Push Payload

The payload format looks like this:

- `wcs`: Webclient session (sha256 hash of the public permanent key of the
  initiator), `string`
- `wca`: An optional identifier for affiliating consecutive pushes, `string` or `null`
- `wct`: Unix epoch timestamp of the request in seconds, `i64`
- `wcv`: Protocol version, `u16`

### FCM / HMS

The FCM and HMS messages contain the payload data as specified above.

### APNs

The APNs message contains a key "3mw" containing the payload data as specified
above.

## Running

You need the Rust compiler. First, create a `config.toml` file that looks like this:

    [fcm]
    api_key = "your-api-key"

    [apns]
    keyfile = "your-keyfile.p8"
    key_id = "AB123456XY"
    team_id = "CD987654YZ"

To support HMS as well, you need to add one or more named HMS config sections.

    [hms.credentials_a]
    client_id = "your-client-id"
    client_secret = "your-client-secret"

    [hms.credentials_b]
    client_id = "your-client-id"
    client_secret = "your-client-secret"

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
- Set `RUST_LOG=info` env variable

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
[ci]: https://github.com/threema-ch/push-relay/actions?query=workflow%3ACI
[ci-badge]: https://img.shields.io/github/workflow/status/threema-ch/push-relay/CI/master
[license]: https://github.com/threema-ch/push-relay#license
[license-badge]: https://img.shields.io/badge/License-Apache%202.0%20%2f%20MIT-blue.svg
