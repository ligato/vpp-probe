# Releasing vpp-probe

Release of vpp-probe is handled by [GoReleaser](https://github.com/goreleaser/goreleaser/). 

Publishing of Docker images and GitHub releases is automated via GitHub CI [Release workflow](https://github.com/ligato/vpp-probe/actions/workflows/release.yml).

## Snapshot release

## Prerequisites

- [Go 1.14+](https://golang.org/dl/)
- [GoReleaser](https://goreleaser.com/install/)
- [Docker](https://docs.docker.com/get-docker/)


To release a snapshot of vpp-probe run:

```sh
goreleaser release --rm-dist --snapshot
```

Now you can find the release files under `dist` directory.
