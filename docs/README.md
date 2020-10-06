# VPP Probe

VPP probe is a command-line tool for inspection and monitoring of VPP instances.

### Instance Discovery

TBD..

### Packet Tracer


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

### Inspection Probe

TBD..
