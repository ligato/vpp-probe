<h1 align="center">vpp-probe</h1>
<p align="center">
    <a href="https://github.com/ligato/vpp-probe/actions/workflows/ci.yml"><img src="https://github.com/ligato/vpp-probe/actions/workflows/ci.yml/badge.svg"></a> <a href="https://github.com/ligato/vpp-probe/actions/workflows/release.yml"><img src="https://github.com/ligato/vpp-probe/actions/workflows/release.yml/badge.svg"></a> <a href="https://github.com/ligato/vpp-probe/releases"><img alt="GitHub Releases" src="https://img.shields.io/github/v/release/ligato/vpp-probe?include_prereleases&logo=github&logoColor=white&label=latest%20version"></a> <a href="https://cloud.docker.com/u/ligato/repository/docker/ligato/vpp-probe"><img alt="Docker Image Version" src="https://img.shields.io/docker/pulls/ligato/vpp-probe?logo=docker&logoColor=white"></a>
</p>

---

## Intro

VPP-probe is a command-line tool for inspecting and monitoring of VPP instances running in any kind of environment (_Kubernetes_, _Docker_, _Local_). It aims to help during debugging of issues that occur in the distributed systems containing several VPP instances.

### Features

- **Instance Discovery** - discover VPP instances in the target system environment
- **Packet Tracing** - trace packets from multiple VPP instances while executing arbitrary command 
- **Command Execution** - execute commands on multiple VPP instances at once 
- **Topology Auto-Correlation** - automatic correlation of connections across VPP instances

## Install

You can get vpp-probe by downloading a pre-compiled binary, using the official Docker image or building it from source.

### Download a pre-compiled binary

Go to [GitHub Releases](https://github.com/ligato/vpp-probe/releases) and download a binary pre-compiled for your system.

### Get Docker image

Go to [DockerHub Tags](https://hub.docker.com/r/ligato/vpp-probe/tags) for list of available tags.

##### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) is required

```sh
# Pull the latest image
docker pull ligato/vpp-probe

# Print version
docker run --rm -it ligato/vpp-probe version
```

### Build from source

##### Prerequisites

- [Go 1.15+](https://golang.org/doc/install) is required

To install vpp-probe from source simply run:

```sh
# Install the latest version
go install go.ligato.io/vpp-probe@latest
# if you have Go older than 1.16 run: GO111MODULE=on go get go.ligato.io/vpp-probe

# Print version
vpp-probe version
```

## Quick Start

Where is your VPP running?

<details>

<summary><h2>Kubernetes</h2></summary>

Basic commands for VPP running in a Kubernetes pod

```sh
# Discover VPP instances in a cluster
vpp-probe --env=kube discover

# Execute a command on all VPP instances
vpp-probe --env=kube exec -- "vppctl show counters"

# Trace packets on all VPP instances for the duration of ping command
vpp-probe --env=kube trace "kubectl exec -it mypod -- ping -c 1 10.10.1.1"
```

Specify target cluster(s) (kubeconfig/context)

```sh
# Run on different cluster by providing custom kubeconfig and/or context
vpp-probe --kubeconfig="my.kubeconfig" <command>
vpp-probe --kubecontext="kind-2"       <command>

# Run on multiple clusters by adding another kubeconfig/context separated by comma
vpp-probe --kubeconfig="kubeconfig1,kubeconfig2" <command>
vpp-probe --kubecontext="kind-2,kind-3"          <command>
```

When running vpp-probe from Docker image

```sh
# Run from Docker image
docker run -it --net=host --volume "$HOME/.kube/config:/.kube/config" ligato/vpp-probe --env=kube <command>
```

</details>

<details>

<summary>Docker</summary>

Basic commands for VPP running in a Docker container

```sh
# Discover VPP instances in Docker
vpp-probe --env=docker discover

# Execute a command on all VPP instances
vpp-probe --env=docker exec -- "vppctl show counters"

# Trace packets on all VPP instances for the duration of ping command
vpp-probe --env=docker trace "docker exec -it mycontainer ping -c 1 172.17.0.3"
```

Specify a different Docker daemon

```sh
# Run on different docker host
vpp-probe --dockerhost="/var/run/docker2.sock" <command>
```

When running vpp-probe from Docker image

```sh
# Run from Docker image
docker run -it --net=host --volume "/var/run/docker.sock:/var/run/docker.sock" ligato/vpp-probe --env=docker <command>
```

</details>

<details>

<summary>Local</summary>

Basic commands for VPP running locally

```sh
# Discover VPP instances running as local process
vpp-probe --env=local discover

# Execute a command on all VPP instances
vpp-probe --env=local exec -- "vppctl show counters"

# Trace packets on all VPP instances for the duration of ping command
vpp-probe --env=local trace "ping -c 1 192.168.1.1"
```

When running vpp-probe from Docker image

```sh
# Run from Docker image
docker run -it --net=host --pid=host --volume "/run/vpp:/run/vpp" ligato/vpp-probe --env=local <command>
```

</details>

---

For more detailed usage information, read [docs/USAGE.md](docs/USAGE.md)

## Testing

```sh
# Run integration tests
go test ./test/integration

# Run e2e tests
go test ./test/e2e
```

For more information about testing, read [docs/TESTING.m](docs/TESTING.md)

## Development

Read [docs/DEVELOP.md](docs/DEVELOP.md) for information about vpp-probe development.
