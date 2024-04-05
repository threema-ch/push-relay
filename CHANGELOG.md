# Changelog

This project follows semantic versioning.

Possible log types:

- `[added]` for new features.
- `[changed]` for changes in existing functionality.
- `[deprecated]` for once-stable features removed in upcoming releases.
- `[removed]` for features removed in this release.
- `[fixed]` for any bug fixes.
- `[security]` to invite users to upgrade in case of vulnerabilities.

### Unreleased

- [changed] Updated dependencies

### [v4.2.3][v4.2.3] (2024-02-02)

- [changed] Updated dependencies

### [v4.2.2][v4.2.2] (2023-11-14)

- [changed] Updated dependencies

### [v4.2.1][v4.2.1] (2023-07-05)

- [changed] Improved logging

### [v4.2.0][v4.2.0] (2023-06-27)

- [added] Support for Threema Gateway push (#52)
- [changed] Updated dependencies

### [v4.1.1][v4.1.1] (2022-03-31)

- [added] Log APNs push type (#49)
- [changed] Updated dependencies

### [v4.1.0][v4.1.0] (2022-03-17)

- [added] APNs: Support non-silent push notifications as well (#46)
- [changed] Updated dependencies

### [v4.0.0][v4.0.0] (2021-03-15)

- [added] Support for HMS
- [added] FCM: Support for connection reuse and TLS session resumption
- [changed] The config file format was changed from INI to TOML and the default
  filename was changed from `config.ini` to `config.toml`. Since TOML is a
  superset of INI, the existing config should remain valid. But the change
  simplifies parsing and allows more data types (like lists and maps).

### [v3.4.0][v3.4.0] (2020-01-13)

- [security] Updated dependencies, including a [security update in a transitive
  dependency][rustsec-2019-033]
- [changed] Require at least Rust 1.36 to build (previous: 1.33)

[rustsec-2019-033]: https://rustsec.org/advisories/RUSTSEC-2019-0033.html


### [v3.3.0][v3.3.0] (2019-08-05)

- [security] Updated dependencies, including a [security update in a transitive
  dependency][memoffset-9]
- [changed] Require at least Rust 1.33 to build (previous: 1.31)

[memoffset-9]: https://github.com/Gilnaa/memoffset/issues/9


### [v3.2.1][v3.2.1] (2019-07-08)

- [security] Updated dependencies, including a [security update in a transitive
  dependency][smallvec-148] (#29)

[smallvec-148]: https://github.com/servo/rust-smallvec/issues/148


### [v3.2.0][v3.2.0] (2019-05-23)

- [added] APNS: Apply `collapse_key` and `ttl` if specified (#24)
- [fixed] APNs: Use timestamp based on TTL instead of the TTL itself (#25)
- [changed] Refined error handling (#26)


### [v3.1.0][v3.1.0] (2019-04-25)

- [added] Allow clients to override the FCM TTL (#19)
- [added] Allow clients to override the FCM collapse key (#20)
- [changed] Improve handling of FCM push errors (#18)


### [v3.0.0][v3.0.0] (2019-01-24)

- [changed] Use new FCM API endpoint
- [changed] Rename `[gcm]` section in config.ini to `[fcm]`
- [changed] Rename `type=gcm` request key to `type=fcm`
  (the `gcm` version will still work but is deprecated)


### [v2.2.0][v2.2.0] (2018-12-17)

- [changed] Switch to Rust 2018 edition
- [changed] Require at least Rust 1.31 to build (previous: 1.30)
- [changed] Updated dependencies
- [changed] Increase log level for some logs
- [changed] Apply clippy lint feedback


[v2.2.0]: https://github.com/threema-ch/push-relay/compare/v2.1.1...v2.2.0
[v3.0.0]: https://github.com/threema-ch/push-relay/compare/v2.2.0...v3.0.0
[v3.1.0]: https://github.com/threema-ch/push-relay/compare/v3.0.0...v3.1.0
[v3.2.0]: https://github.com/threema-ch/push-relay/compare/v3.1.0...v3.2.0
[v3.2.1]: https://github.com/threema-ch/push-relay/compare/v3.2.0...v3.2.1
[v3.3.0]: https://github.com/threema-ch/push-relay/compare/v3.2.1...v3.3.0
[v3.4.0]: https://github.com/threema-ch/push-relay/compare/v3.3.0...v3.4.0
[v4.0.0]: https://github.com/threema-ch/push-relay/compare/v3.4.0...v4.0.0
[v4.1.0]: https://github.com/threema-ch/push-relay/compare/v4.0.0...v4.1.0
[v4.1.1]: https://github.com/threema-ch/push-relay/compare/v4.1.0...v4.1.1
[v4.2.0]: https://github.com/threema-ch/push-relay/compare/v4.1.1...v4.2.0
[v4.2.1]: https://github.com/threema-ch/push-relay/compare/v4.2.0...v4.2.1
[v4.2.2]: https://github.com/threema-ch/push-relay/compare/v4.2.1...v4.2.2
[v4.2.2]: https://github.com/threema-ch/push-relay/compare/v4.2.2...v4.2.3
