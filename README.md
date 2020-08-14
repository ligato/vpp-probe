<p align="center">

```
                                                    ______       
 ___   _________________       ________________________  /______ 
 __ | / /__  __ \__  __ \_________  __ \_  ___/  __ \_  __ \  _ \
 __ |/ /__  /_/ /_  /_/ //_____/_  /_/ /  /   / /_/ /  /_/ /  __/
 _____/ _  .___/_  .___/       _  .___//_/    \____//_.___/\___/ 
        /_/     /_/            /_/                               
```

</p>

A CLI tool for examining VPP instances

## Packet Tracer

Packet tracer connects to multiple VPP instances inside Kubernetes cluster and
collects packet traces that can be further analyzed via terminal UI.

### Preview

[![asciicast](https://asciinema.org/a/Pp5IOFRNWEgT5JhrOn3kYHfI5.svg)](https://asciinema.org/a/Pp5IOFRNWEgT5JhrOn3kYHfI5)

Example usage:

```sh
$ vpp-probe tracer --kubeconfig $HOME/kubeconfigs/nsm/kind-1.kubeconfig \
    networkservicemesh.io/app=vl3-nse-bar \
    app=nsm-vpp-plane
```

Flags:

```sh
$ vpp-probe tracer --help
Analyze packet traces in VPP

Usage:
  vpp-probe tracer [flags] LABELS

Flags:
      --all strings         List of traced nodes (default [af-packet-input,avf-input,bond-process,memif-input,p2p-ethernet-input,pg-input,punt-socket-rx,rdma-input,session-queue,tuntap-rx,vhost-user-input,virtio-input,vmxnet3-input])
  -d, --duration duration   Duration of tracing (default 3s)
  -h, --help                help for tracer
      --kubeconfig string   Path to kubeconfig
  -t, --target string       Target to trace

Global Flags:
  -D, --debug   Enable debug mode
```

## Install

// TBD