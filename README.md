```
    ___    _________________                        ______       
    __ |  / /__  __ \__  __ \   _______________________  /______ 
    __ | / /__  /_/ /_  /_/ /  ___  __ \_  ___/  __ \_  __ \  _ \
    __ |/ / _  ____/_  ____/   __  /_/ /  /   / /_/ /  /_/ /  __/
    _____/  /_/     /_/           .___//_/    \____//_.___/\___/ 
                                /_/                               
```
> Inspect and monitor VPP instances running anywhere

### Table of Contents

- [Introduction](#Introduction)
- [Features](#features)
- [Install](#Install)
- [Usage](#Usage)

---

## Introduction

VPP probe is a command-line tool for inspecting and monitoring of VPP instances. 

## Features

* Instance Discovery - discover VPP instances in any environment: a Kubernetes pod, a Docker container or just locally on your host
* Interactive Inspector - inspect VPP instances using an interactive terminal UI providing an overview of instances
* Packet Tracing - trace packets from multiple VPP instances while executing ping command between them 

## Install

Prerequisites:
- [Go 1.14+](https://golang.org/dl/)

To install vpp-probe run:

```sh
git clone https://github.com/ligato/vpp-probe.git
cd vpp-probe
go install
```

> NOTE: Remember to set `GOPATH` to the directory where you want pprof to be installed. The binary will be in `$GOPATH/bin`, ensure that directory is in your `PATH`

## Usage

To specify the environment where VPP is running use option `--env=<ENV>`, supported values are: `local`, `kube` and `docker`.

To specify the query parameters use option `--query=<PARAMS>`, where query parameters are separated by a semicolon `;`.
Multiple queries per command are supported by adding multiple `--query` options.

### Discover

Discover VPP instances running in Kubernetes pods by specifying a label selector:

```sh
vpp-probe --env="kube" --query="label=app=wcm-nsm-vpp-forwarder" discover
```

To include additional output from VPP CLI commands add option `--printclis`. To add extra VPP CLI commands use option `--extraclis`, to add multiple commands separate them by a comma.

### Trace

Trace packets from multiple VPP instances while running ping command:

```sh
vpp-probe --env="kube" --query "label=app=wcm-nsm-vpp-forwarder" trace --cmd "kubectl exec -it helloworld-example-d86575f96-m5m59 -- ping 172.100.244.5"
```
