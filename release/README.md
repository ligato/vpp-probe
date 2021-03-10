> Releasing of vpp-probe binaries for linux/darwin

### Table of Contents

- [Prerequisites](#Prerequisites)
- [Usage](#Usage)

---

## Prerequisites

- [Go 1.14+](https://golang.org/dl/)
- [export GITHUB_TOKEN env](https://github.com/settings/tokens/new)
- [valid SemVer2 tag on latest commit](https://semver.org/#backusnaur-form-grammar-for-valid-semver-versions)
- clean state of Git repo

## Usage

To release vpp-probe binaries using latest version of [GoReleaser](https://github.com/goreleaser/goreleaser/) run:

```sh
cd release && ./goreleaser.sh
```

Example of usage when integrating with a CI tool (that can leave Git repo in a dirty state - modifying `go.sum` for example):

```sh
cd release && git stash && VERSION="v0.157.0" ./goreleaser.sh
```


