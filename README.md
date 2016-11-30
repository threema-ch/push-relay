# FCM Push Relay

This server accepts push requests via HTTP and notifies the FCM push service.

## Request Format

- POST request to `/push`
- Request body must use `application/x-www-form-urlencoded` encoding
- The keys `token` (FCM token) and `session` (public permanent key of the initiator) must be present

Example:

    curl -X PSOT [::1]:3000/push -d "token=asdf&session=123deadbeef"

Possible response codes:

- `HTTP 204 (No Content)`: Request was processed successfully
- `HTTP 400 (Bad Request)`: Invalid or missing POST parameters

## Running

You need the Rust compiler. Then simply run

    cargo run

...to build and start the server in debug mode.

## Deployment

- Always create a build in release mode: `cargo build --release`
- Use a reverse proxy with proper TLS termination (e.g. Nginx)
