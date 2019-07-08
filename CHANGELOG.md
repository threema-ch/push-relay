# Changelog

This project follows semantic versioning.

Possible log types:

- `[added]` for new features.
- `[changed]` for changes in existing functionality.
- `[deprecated]` for once-stable features removed in upcoming releases.
- `[removed]` for deprecated features removed in this release.
- `[fixed]` for any bug fixes.
- `[security]` to invite users to upgrade in case of vulnerabilities.


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
