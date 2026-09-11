# Releasing

Set variables:

```sh
export VERSION=X.Y.Z
export GPG_KEY=E7ADD9914E260E8B35DFB50665FDE935573ACDA6
```

Update changelog:

```sh
vim CHANGELOG.md
```

Update version numbers:

```sh
vim Cargo.toml
cargo update -p push-relay
```

Commit & tag:

```sh
git commit -S${GPG_KEY} -m "Release v${VERSION}"
git tag -s -u ${GPG_KEY} v${VERSION} -m "Version ${VERSION}"
```

Push:

```sh
git push && git push --tags
```
