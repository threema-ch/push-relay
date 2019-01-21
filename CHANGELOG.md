# Changelog

This project follows semantic versioning.

Possible log types:

- `[added]` for new features.
- `[changed]` for changes in existing functionality.
- `[deprecated]` for once-stable features removed in upcoming releases.
- `[removed]` for deprecated features removed in this release.
- `[fixed]` for any bug fixes.
- `[security]` to invite users to upgrade in case of vulnerabilities.


### Unreleased

- [changed] Rename `[gcm]` section in config.ini to `[fcm]`
- [changed] Rename `type=gcm` request key to `type=fcm`
  (the `gcm` version will still work but is deprecated)
- [changed] Use new FCM API endpoint

### [v2.2.0][v2.2.0] (2018-12-17)

- [changed] Switch to Rust 2018 edition
- [changed] Require at least Rust 1.31 to build (previous: 1.30)
- [changed] Updated dependencies
- [changed] Increase log level for some logs
- [changed] Apply clippy lint feedback


[v2.2.0]: https://github.com/dbrgn/tealdeer/compare/v2.1.1...v2.2.0
