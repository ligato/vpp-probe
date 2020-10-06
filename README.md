```
    ___    _________________                        ______       
    __ |  / /__  __ \__  __ \   _______________________  /______ 
    __ | / /__  /_/ /_  /_/ /  ___  __ \_  ___/  __ \_  __ \  _ \
    __ |/ / _  ____/_  ____/   __  /_/ /  /   / /_/ /  /_/ /  __/
    _____/  /_/     /_/           .___//_/    \____//_.___/\___/ 
                                /_/                               
```
> Inspect and monitor VPP instances running in :cloud:

### Table of Contents

- [Introduction](#Introduction)
- [Features](#features)
- [Install](#Install)
- [Usage](#Usage)
- [Documentation](#Documentation)

---

## Introduction

VPP probe is a command-line tool for inspection and monitoring of VPP instances. It is primarily intended for VPP running in Kuberenetes environment, but works with VPP running on your host locally (Docker environment could be added in the future).  

## Features

#### Instance Discovery

VPP instances can be discovered in Kubernetes cluster by specifying selector of pod labels in which VPP is running.

#### Probe Inspector

VPP probe provides a terminal UI to inspect VPP instances. Retrieving data from VPP can use various different ways to obtain it - CLI, Binary API, Stats API.

#### Packet Tracer

Tracer connects to multiple VPP instances running inside Kubernetes cluster to manage packet tracing. It provides a simple terminal UI for browsing of trace results to help analyze the data.

Preview

<a href="https://asciinema.org/a/353305?autoplay=1&size=medium"><img src="https://asciinema.org/a/353305.svg" width="450"/></a>

## Install

Prerequisites:
- [Go 1.14+](https://golang.org/dl/)

To get the source code

    ```sh
    git clone https://github.com/ligato/vpp-probe.git
    ```

To install vpp-probe
 
    ```sh
    go install ./cmd/vpp-probe
    ```
    
> NOTE: Remember to set `GOPATH` to the directory where you want pprof to be installed. The binary will be in `$GOPATH/bin`, ensure that directory is in your `PATH` 
   
Start probing VPPs! 🔬

## Basic usage

Inspect VPP instances running in pods with specific label

```sh
vpp-probe --selector="app=nsm-vpp-plane"
```

Trace and analyze captured packets from multiple VPP instances

```sh
vpp-probe probe --kubeconfig="$HOME/.kube/config"
```

## Documentation

See [doc/README.md](doc/README.md) for more detailed documentation.
