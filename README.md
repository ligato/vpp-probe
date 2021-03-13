```
    ___    _________________                        ______       
    __ |  / /__  __ \__  __ \   _______________________  /______ 
    __ | / /__  /_/ /_  /_/ /  ___  __ \_  ___/  __ \_  __ \  _ \
    __ |/ / _  ____/_  ____/   __  /_/ /  /   / /_/ /  /_/ /  __/
    _____/  /_/     /_/           .___//_/    \____//_.___/\___/ 
                                /_/                               
```
> Debug VPP instances running anywhere

### Table of Contents

- [Intro](#intro)
- [Features](#features)
- [Install](#install)
- [Quick Start](#quick-start)

---

## Intro

VPP-probe is a command-line tool for inspecting and monitoring of VPP instances. VPP-probe library provides an abstract API for accessing VPP instance(s) running in different host systems; _Kubernetes, Docker, Local_ and the CLI app uses this API to interact with VPP.

## Features

* **Instance Discovery** - discover VPP instances in any environment: a Kubernetes pod, a Docker container or just locally on your host
* **Interactive Inspector** - inspect VPP instances using an interactive terminal UI providing an overview of instances
* **Packet Tracing** - trace packets from multiple VPP instances while executing ping command between them 
* **Command Execution** - execute commands on multiple VPP instances

## Install

### Prerequisites

- [Go 1.15+](https://golang.org/doc/install) is required

To install latest vpp-probe simply run:

```sh
# using go1.16+
go get go.ligato.io/vpp-probe@master

# using go1.15 or older
GO111MODULE=on go get go.ligato.io/vpp-probe@master
```

## Quick Start

To specify the environment where VPP is running use option `--env=<ENV>`, supported values are: `local`, `kube` and `docker`.

```sh
# Discover VPP instances in your current cluster
vpp-probe --env=kube discover

# Run custom command for all VPP instances
vpp-probe --env=kube exec -- agentctl config history --details
```

For detailed usage information, read [USAGE document](docs/USAGE.md)
