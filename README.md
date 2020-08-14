```
    ___    _________________                        ______       
    __ |  / /__  __ \__  __ \   _______________________  /______ 
    __ | / /__  /_/ /_  /_/ /_____  __ \_  ___/  __ \_  __ \  _ \
    __ |/ / _  ____/_  ____/_____  /_/ /  /   / /_/ /  /_/ /  __/
    _____/  /_/     /_/        _  .___//_/    \____//_.___/\___/ 
                                /_/                               
```
> Developer tool for inspecting VPP instances running in the cloud :cloud:

<hr>

## Contents
- [Install](#install)
- [Packet Tracer](#packet-tracer)

## Install

#### Requirements
- [Go 1.14+](https://golang.org/dl/)

```sh
git clone https://github.com/ligato/vpp-probe.git
cd vpp-probe
go install ./cmd/vpp-probe 
```

<br>

## Packet Tracer

Packet tracer connects to multiple VPP instances inside Kubernetes cluster and
collects packet traces that can be further analyzed via terminal UI.

#### Preview

<a href="https://asciinema.org/a/353305?autoplay=1&size=medium"><img src="https://asciinema.org/a/353305.svg" width="450"/></a>

#### Usage

```sh
vpp-probe tracer --kubeconfig "$HOME/kubeconfigs/nsm/kind-1.kubeconfig" \
    networkservicemesh.io/app=vl3-nse-bar \
    app=nsm-vpp-plane
```

<details>
<summary><b>All <code>tracer</code> options</b></summary>
<br>


```sh
$ vpp-probe tracer --help
Analyze packet traces in VPP

Usage:
  vpp-probe tracer [flags]

Flags:
  -h, --help                 help for tracer
      --kubeconfig string    Path to kubeconfig
  -d, --tracedur duration    Duration of tracing (default 3s)
      --tracenodes strings   List of traced nodes (default [af-packet-input,avf-input,bond-process,memif-input,p2p-ethernet-input,pg-input,punt-socket-rx,rdma-input,session-queue,tuntap-rx,vhost-user-input,virtio-input,vmxnet3-input])

Global Flags:
  -D, --debug   Enable debug mode
```


<br>
</details>
