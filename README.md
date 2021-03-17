<h1 align="center">vpp-probe</h1>
<p align="center">
    <a href="https://github.com/ligato/vpp-probe/actions/workflows/ci.yml"><img src="https://github.com/ligato/vpp-probe/actions/workflows/ci.yml/badge.svg"></a>
</p>

Debug VPP instances running anywhere.

### Table of Contents

* [Intro](#intro)
* [Install](#Install)
* [Quick Start](#quick-start)
* [Testing](#Testing)

---

## Intro

VPP-probe is a command-line tool for inspecting and monitoring of VPP instances. VPP-probe library provides an abstract API for accessing VPP instance(s) running in different host systems; _Kubernetes, Docker, Local_ and the CLI app uses this API to interact with VPP.

### Features

* **Instance Discovery** - discover VPP instances in any environment: a Kubernetes pod, a Docker container or just locally on your host
* **Interactive Inspector** - inspect VPP instances using an interactive terminal UI providing an overview of instances
* **Packet Tracing** - trace packets from multiple VPP instances while executing ping command between them 
* **Command Execution** - execute commands on multiple VPP instances

## Install

#### Prerequisites

- [Go 1.15+](https://golang.org/doc/install) is required

To install latest vpp-probe simply run:

```sh
GO111MODULE=on go get go.ligato.io/vpp-probe

vpp-probe version
```

## Quick Start

### Kubernetes

```sh
# Discover VPP instances in a cluster
vpp-probe --env=kube discover

# Execute a command on all VPP instances
vpp-probe --env=kube exec -- "agentctl config history --details"

# Trace packets on all VPP instances for 5 seconds
vpp-probe --env=kube trace "sleep 5"

# Run on different cluster by providing custom kubeconfig and/or context
vpp-probe --kubeconfig="my.kubeconfig" <command>
vpp-probe --kubecontext="kind-2"       <command>

# Run on multiple clusters by adding another kubeconfig/context separated by comma
vpp-probe --kubeconfig="kubeconfig1,kubeconfig2" <command>
vpp-probe --kubecontext="kind-2,kind-3"          <command>
```

### Docker

```sh
# Discover VPP instances in Docker
vpp-probe --env=docker discover

# Execute a command on all VPP instances
vpp-probe --env=kube exec -- "agentctl config history --details"

# Trace packets on all VPP instances for 5 seconds
vpp-probe --env=kube trace "ping -c 1 172.17.0.3"

# Run on different docker host
vpp-probe --dockerhost="/var/run/docker2.sock" <command>
```

For detailed usage information, read [USAGE document](docs/USAGE.md)

## Testing

```sh
# Run integration tests
go test ./test/integration

# Run e2e tests
go test ./test/e2e
```

For more information about testing, read [TESTING document](docs/TESTING.md)
