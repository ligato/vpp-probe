# Usage of vpp-probe

##### Table of contents
- [`vpp-probe`](#vpp-probe)
  - [`discover`](#discover)
  - [`exec`](#exec)
  - [`tracer`](#tracer)

## vpp-probe

<details open>
<summary><code>vpp-probe --help</code></summary>

```
 ___    _________________                        ______         
 __ |  / /__  __ \__  __ \   _______________________  /______  
 __ | / /__  /_/ /_  /_/ /_____  __ \_  ___/  __ \_  __ \  _ \ 
 __ |/ / _  ____/_  ____/_____  /_/ /  /   / /_/ /  /_/ /  __/ 
 _____/  /_/     /_/        _  .___//_/    \____//_.___/\___/  
                            /_/

Usage:
  vpp-probe [command]

Available Commands:
  discover    Discover running VPP instances
  help        Help about any command
  tracer      Trace packets from VPP instances

Flags:
  -e, --env string           Environment type in which VPP is running. Supported environments are local, docker and kube,
                             where VPP is running as a local process, as a Docker container or as a Kubernetes pod, respectivelly.
                             
  -q, --query stringArray    Selector query to filter VPP instances on, supports '=' (e.g --query key1=value1). 
                             Multiple parameters in a single query (using AND logic) are separated by a comma (e.g. -q key1=val1,key2=val2) and 
                             multiple queries (using OR logic) can be defined as additional flag options (e.g. -q k1=v1 -q k1=v2). 
                             Parameter types depend on probe environment (defined with --env).
                             
      --kubeconfig string    Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG) (used in kube env)
      --kubecontext string   The name of the kubeconfig context to use (used in kube env)
                             
      --dockerhost string    Daemon socket(s) to connect to (used in docker env)
                             
      --clisock string       Path to VPP CLIsocket file (used in local env)
      --apisock string       Path to VPP binary API socket file (used in local env)
      --statsock string      Path to VPP stats API socket file (used in local env)
                             
  -D, --debug                Enable debug mode
  -L, --loglevel string      Set logging level
  -v, --version              version for vpp-probe

Use "vpp-probe [command] --help" for more information about a command.
```

</details>

### Global Options

The vpp-probe root command has several global options used for setting up probe providers and filter the VPP instances.

#### Environment

`--env`/`-e` - specifies environment where VPP instances are running
- `kube` - VPP instance(s) running in Kubernetes pod
- `docker` - VPP instance(s) running in Docker container
- `local` - VPP instance running locally

#### Query

`--query`/`-e` - specifies query parameters for selecting/filtering VPP instances
- actual supported parameters depend on selected environment (listed below)
- multiple parameters in single query (use __AND__ logic) and are separated by a comma, e.g. `-q "param1=value1,param2=value2"`
- multiple queries (use __OR__ logic) can be specified with additional flag, e.g. `-q param1=value1 -q param2=value2`

### Kubernetes env

Set `--env=kube` to access VPP instances running on pods in Kubernetes cluster(s) specified with `--kubeconfig` and `--kubecontext` flags.

```
--kubeconfig string    Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG)
--kubecontext string   The name of the kubeconfig context to use (multiple contexts separated by a comma `,`)
```

The `KUBECONFIG` env var, behaves the same way as in `kubectl`, which supports [merging multiple kubeconfig files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/#merging-kubeconfig-files). This allows using contexts from multiple kubeconfigs.

```sh
export KUBECONFIG="/path/to/kubeconfig1:/path/to/kubeconfig2"
vpp-probe --kubecontext="ctx1,ctx2" -q "label=app=vpp" discover
```

##### Query parameters

|Parameter|Type|Description|
|---|---|---|
|`name`|string|Pod name|
|`namespace`|string|Pod namespace|
|`label`|string|Label selector|
|`field`|string|Field selector|

Multiple kubeconfigs separated by `:` and multiple contexts separated by `,`.

### Docker env

Set `--env=docker` to access VPP instances running in Docker container(s).

```
--dockerhost string    Daemon socket(s) to connect to (used in docker env)
```

##### Query parameters

|Parameter|Type|Description|
|---|---|---|
|`id`|string|Container ID|
|`name`|string|Container name|
|`label`|string|Label selector|

### Local env

Set `--env=local` to access VPP instances running locally on the host.

```
--clisock string       Path to VPP CLIsocket file (used in local env)
--apisock string       Path to VPP binary API socket file (used in local env)
--statsock string      Path to VPP stats API socket file (used in local env)
```

##### Query parameters
No query parameters support for local env.

## discover

The `discover` command will look for VPP instances in [selected environment](#environment) and retrieve basic VPP info and interfaces configured for VPP/Linux. The [`--query` flag](#query) **is not required**, but can be used to set parameters for selecting only some of the instances or even specify exact instance.

<details open>
<summary><code>vpp-probe discover --help</code></summary>

```sh
Discover running VPP instances

Usage:
  vpp-probe discover [flags]

Examples:
  # Discover VPP instances in Kubernetes pods with label "app=vpp"
  vpp-probe discover -e kube -q "label=app=vpp"

  # Discover VPP instances in Docker container with name "vpp1"
  vpp-probe discover -e docker -q  "name=vpp1"

  # Discover instances running locally
  vpp-probe discover

Flags:
      --extraclis strings   Additional CLI commands to run for each instance.
  -f, --format string       Output format.
  -h, --help                help for discover
      --printclis           Print output from CLI commands for each instance.
```
</details>

<details>
<summary>Example</summary>

```
$ vpp-probe --kubecontext="cluster1,cluster2"  --query "label=networkservicemesh.io/app=vl3-nse-bar" --query="label=app=wcm-nsm-vpp-forwarder" discover            
----------
= Instance: map[cluster:kind-kind-2 created:Thu Jan  7 18:34:05 CET 2021 env:kube ip:10.244.0.17 namespace:wcm-system pod:vl3-nse-bar-66b4fb99d9-dfwzf uid:0c293e71-dcc6-4a1f-882b-2d40d9462bc4]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE	TYPE	STATE	IP			VRF	MTU	DETAILS										OTHER	
  2	bar498hf	MEMIF	up	172.100.248.6/30	0	0	socket:/var/lib/networkservicemesh/nsmK1XbEPWK2/memif.sock master:true 	
  1	bar8wc6b	MEMIF	up	172.100.248.2/30	0	0	socket:/var/lib/networkservicemesh/nsmXG3kEPWwt/memif.sock master:true 	

2 vpp interfaces

----------
= Instance: map[cluster:kind-kind-2 created:Thu Jan  7 18:34:05 CET 2021 env:kube ip:10.244.0.16 namespace:wcm-system pod:vl3-nse-bar-66b4fb99d9-hchwr uid:fda7b201-a00f-40bd-bc64-b06f2c4ef853]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE			TYPE	STATE	IP			VRF	MTU	DETAILS										OTHER	
  3	bar498hf			MEMIF	up	172.100.244.1/30	0	0	socket:/var/lib/networkservicemesh/bar498hf/memif.sock 				
  2	bark9xnj			MEMIF	up	172.100.248.1/30	0	0	socket:/var/lib/networkservicemesh/bark9xnj/memif.sock 				
  4	barrfslq			MEMIF	up	172.100.240.1/30	0	0	socket:/var/lib/networkservicemesh/barrfslq/memif.sock 				
  1	helloworld-bar-5d459ccb88-cqdh8MEMIF	up	172.100.252.2/30	0	0	socket:/var/lib/networkservicemesh/nsmAUFxvg5wK/memif.sock master:true 	

4 vpp interfaces

----------
= Instance: map[cluster:kind-kind-2 created:Thu Jan  7 18:28:45 CET 2021 env:kube ip:172.19.0.4 namespace:nsm-system pod:wcm-nsm-vpp-forwarder-ld2rd uid:47084545-2371-4fd4-aa16-22e21d086dfd]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE	TYPE		STATE	IP					VRF	MTU	DETAILS										OTHER	
  2	DST-1		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-28/nsmAUFxvg5wK/memif.sock 			(l2xc to SRC-1)
  4	DST-5		VXLAN_TUNNEL	up						0	0	src:172.19.0.4 -> dst:172.19.0.5 (vni:2)				(l2xc to SRC-5)
  6	DST-6		VXLAN_TUNNEL	up						0	0	src:172.19.0.4 -> dst:172.19.0.5 (vni:4)				(l2xc to SRC-6)
  8	DST-7		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-21/nsmK1XbEPWK2/memif.sock 			(l2xc to SRC-7)
  3	SRC-1		TAP		up						0	1450	host_ifname:tap-1015135623 version:2							(l2xc to DST-1)
  5	SRC-5		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-28/bar498hf/memif.sock master:true 	(l2xc to DST-5)
  7	SRC-6		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-28/barrfslq/memif.sock master:true 	(l2xc to DST-6)
  9	SRC-7		VXLAN_TUNNEL	up						0	0	src:172.19.0.4 -> dst:172.19.0.5 (vni:3)				(l2xc to DST-7)
  1	mgmt		AF_PACKET	up	172.19.0.4/16 fd24:f853:ccd:e793::4/64	0	0	host_if_name:eth0									

9 vpp interfaces

1 linux interfaces:
 - name:"SRC-1" type:TAP_TO_VPP namespace:{type:FD reference:"/proc/6071/ns/net"} host_if_name:"nsm0" enabled:true ip_addresses:"172.100.252.1/30" mtu:1450 tap:{vpp_tap_if_name:"SRC-1"}:

----------
= Instance: map[cluster:kind-kind-3 created:Thu Jan  7 18:34:17 CET 2021 env:kube ip:10.244.0.16 namespace:wcm-system pod:vl3-nse-bar-66b4fb99d9-hr472 uid:0f67bba3-5e33-4dc4-ab34-9b9c35e99b15]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE	TYPE	STATE	IP			VRF	MTU	DETAILS										OTHER	
  2	bar498hf	MEMIF	up	172.100.240.6/30	0	0	socket:/var/lib/networkservicemesh/nsmvsp7nk0I9/memif.sock master:true 	
  1	bar8wc6b	MEMIF	up	172.100.240.2/30	0	0	socket:/var/lib/networkservicemesh/nsm4J4xni0IW/memif.sock master:true 	

2 vpp interfaces

----------
= Instance: map[cluster:kind-kind-3 created:Thu Jan  7 18:34:17 CET 2021 env:kube ip:10.244.0.17 namespace:wcm-system pod:vl3-nse-bar-66b4fb99d9-s4jpn uid:383a77e7-3ecf-4c76-8cec-12bc04420c60]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE			TYPE	STATE	IP			VRF	MTU	DETAILS										OTHER	
  1	bar8wc6b			MEMIF	up	172.100.244.2/30	0	0	socket:/var/lib/networkservicemesh/nsmA50GeutD/memif.sock master:true 	
  4	bark9xnj			MEMIF	up	172.100.248.5/30	0	0	socket:/var/lib/networkservicemesh/bark9xnj/memif.sock 				
  3	barrfslq			MEMIF	up	172.100.240.5/30	0	0	socket:/var/lib/networkservicemesh/barrfslq/memif.sock 				
  2	helloworld-bar-75cf458c88-nt4h2MEMIF	up	172.100.244.6/30	0	0	socket:/var/lib/networkservicemesh/nsmJsPZa7KRD/memif.sock master:true 	

4 vpp interfaces

----------
= Instance: map[cluster:kind-kind-3 created:Thu Jan  7 18:30:58 CET 2021 env:kube ip:172.19.0.5 namespace:nsm-system pod:wcm-nsm-vpp-forwarder-9skvw uid:fcf3508d-010f-4d5b-8be0-3f0933cc9998]
----------
 Version: 20.05.1-6~gf53edbc3b~b1

IDX	INTERFACE	TYPE		STATE	IP					VRF	MTU	DETAILS										OTHER	
  2	DST-1		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-11/nsmA50GeutD/memif.sock 			(l2xc to SRC-1)
  4	DST-3		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-6/nsm4J4xni0IW/memif.sock 			(l2xc to SRC-3)
  6	DST-5		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-11/nsmJsPZa7KRD/memif.sock 			(l2xc to SRC-5)
  8	DST-9		VXLAN_TUNNEL	up						0	0	src:172.19.0.5 -> dst:172.19.0.4 (vni:3)				(l2xc to SRC-9)
  3	SRC-1		VXLAN_TUNNEL	up						0	0	src:172.19.0.5 -> dst:172.19.0.4 (vni:2)				(l2xc to DST-1)
  5	SRC-3		VXLAN_TUNNEL	up						0	0	src:172.19.0.5 -> dst:172.19.0.4 (vni:4)				(l2xc to DST-3)
  7	SRC-5		TAP		up						0	1450	host_ifname:tap-948025147 version:2							(l2xc to DST-5)
  9	SRC-9		MEMIF		up						0	1450	socket:/var/lib/networkservicemesh/nsm-11/bark9xnj/memif.sock master:true 	(l2xc to DST-9)
  1	mgmt		AF_PACKET	up	172.19.0.5/16 fd24:f853:ccd:e793::5/64	0	0	host_if_name:eth0									

9 vpp interfaces

1 linux interfaces:
 - name:"SRC-5" type:TAP_TO_VPP namespace:{type:FD reference:"/proc/5517/ns/net"} host_if_name:"nsm0" enabled:true ip_addresses:"172.100.244.5/30" mtu:1450 tap:{vpp_tap_if_name:"SRC-5"}:

```

</details>

## exec

The `exec` command will execute custom command on selected VPP instances. The [`--query` flag](#query) **is not required**, but can be used to set parameters for selecting only some of the instances or even specify exact instance, if no query parameters are specified, the command will be executed on all available VPP instances.

<details open>
<summary><code>vpp-probe exec --help</code></summary>

```sh
Execute command on VPP instances

Usage:
  vpp-probe exec [options] command [command...] [flags]

Flags:
  -f, --format string   Output format (json, yaml, go-template..)
  -h, --help            help for exec

Global Flags:
      --apisock string      Path to VPP binary API socket file (used in local env)
      --clisock string      Path to VPP CLIsocket file (used in local env)
  -D, --debug               Enable debug mode
      --dockerhost string   Daemon socket(s) to connect to (implies docker env)
                            
  -e, --env string          Environment type in which VPP is running. Supported environments are local, docker and kube,
                            where VPP is running as a local process, as a Docker container or as a Kubernetes pod, respectivelly.
                            
      --kubeconfig string   Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG) (implies kube env)
      --kubecontext ,       The name of the kubeconfig context to use, multiple contexts separated by a comma , (implies kube env)
                            
  -L, --loglevel string     Set logging level
  -q, --query stringArray   Selector query to filter VPP instances on, supports '=' (e.g --query key1=value1). 
                            Multiple parameters in a single query (using AND logic) are separated by a comma (e.g. -q key1=val1,key2=val2) and 
                            multiple queries (using OR logic) can be defined as additional flag options (e.g. -q k1=v1 -q k1=v2). 
                            Parameter types depend on probe environment (defined with --env).
                            
      --statsock string     Path to VPP stats API socket file (used in local env)
```

</details>

<details>
<summary>Example</summary>

```
$ vpp-probe -e kube exec "agentctl config history"
----------------------------------------------------------------------------------------------------------------------------------
 pod: vl3-nse-bar-686499b8f5-75hff | namespace: wcm-system | node: kind-3-control-plane | cluster: kind-kind-3 | ip: 10.244.0.23
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.217587925s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                              
      0    config replace  6d     16 values  <none>                      <none>                               
      1    config change   6d     2  values  CREATE:6            ok      CONFIGURED:5, PENDING:1              
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      3    status update   6d     2  values  CREATE:2, DELETE:1  ok      CONFIGURED:1, OBTAINED:1, REMOVED:1  
      4    config change   6d     2  values  CREATE:5            ok      CONFIGURED:5                         
      5    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                        
    
----------------------------------------------------------------------------------------------------------------------------------
 pod: vl3-nse-bar-686499b8f5-pcvl9 | namespace: wcm-system | node: kind-3-control-plane | cluster: kind-kind-3 | ip: 10.244.0.22
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.259570126s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                              
      0    config replace  6d     16 values  <none>                      <none>                               
      1    config change   6d     2  values  CREATE:6            ok      CONFIGURED:5, PENDING:1              
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      3    status update   6d     2  values  CREATE:2, DELETE:1  ok      CONFIGURED:1, OBTAINED:1, REMOVED:1  
      4    config change   6d     4  values  CREATE:6            ok      CONFIGURED:5, PENDING:1              
      5    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      6    status update   6d     2  values  CREATE:2, DELETE:1  ok      CONFIGURED:1, OBTAINED:1, REMOVED:1  
    
----------------------------------------------------------------------------------------------------------------------------------
 pod: wcm-nsm-vpp-forwarder-bdxjf | namespace: nsm-system | node: kind-3-control-plane | cluster: kind-kind-3 | ip: 172.19.0.5
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.066952177s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                              
      0    config replace  6d     29 values  <none>                      <none>                               
      1    config change   6d     15 values  CREATE:21           ok      CONFIGURED:21                        
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      3    status update   6d     2  values  CREATE:1, DELETE:1  ok      OBTAINED:1, REMOVED:1                
      4    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      5    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      6    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      7    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      8    config change   6d     6  values  CREATE:9            ok      CONFIGURED:8, PENDING:1              
      9    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                                  
    
----------------------------------------------------------------------------------------------------------------------------------
 pod: vl3-nse-bar-76b6c4787d-drb7x | namespace: wcm-system | node: kind-2-control-plane | cluster: kind-kind-2 | ip: 10.244.0.22
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.404398753s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                              
      0    config replace  6d     16 values  <none>                      <none>                               
      1    config change   6d     2  values  CREATE:6            ok      CONFIGURED:5, PENDING:1              
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      3    status update   6d     2  values  CREATE:2, DELETE:1  ok      CONFIGURED:1, OBTAINED:1, REMOVED:1  
      4    config change   6d     4  values  CREATE:6            ok      CONFIGURED:5, PENDING:1              
      5    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      6    status update   6d     2  values  CREATE:2, DELETE:1  ok      CONFIGURED:1, OBTAINED:1, REMOVED:1  
    
----------------------------------------------------------------------------------------------------------------------------------
 pod: vl3-nse-bar-76b6c4787d-vqrd8 | namespace: wcm-system | node: kind-2-control-plane | cluster: kind-kind-2 | ip: 10.244.0.21
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.434726412s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                              
      0    config replace  6d     16 values  <none>                      <none>                               
      1    config change   6d     1  values  CREATE:5            ok      CONFIGURED:4, PENDING:1              
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      3    config change   6d     2  values  CREATE:5            ok      CONFIGURED:5                         
      4    status update   6d     1  values  CREATE:1            ok      OBTAINED:1                           
      5    config change   6d     2  values  CREATE:5            ok      CONFIGURED:5                         
    
----------------------------------------------------------------------------------------------------------------------------------
 pod: wcm-nsm-vpp-forwarder-285k8 | namespace: nsm-system | node: kind-2-control-plane | cluster: kind-kind-2 | ip: 172.19.0.4
----------------------------------------------------------------------------------------------------------------------------------

  # agentctl config history (took 1.644209131s)
  
      SEQ  TYPE            START  INPUT      OPERATIONS          RESULT  SUMMARY                
      0    config replace  6d     29 values  <none>                      <none>                 
      1    config change   6d     15 values  CREATE:21           ok      CONFIGURED:21          
      2    status update   6d     1  values  CREATE:1            ok      OBTAINED:1             
      3    status update   6d     2  values  CREATE:1, DELETE:1  ok      OBTAINED:1, REMOVED:1  
      4    status update   6d     1  values  CREATE:1            ok      OBTAINED:1             
    
```

</details>


## tracer

The `tracer` command will run arbitrary command, usually `ping`, `curl` or `sleep`, and during execution of the command it will trace packets on selected VPP instances. The [`--query` flag](#query) **is not required**, but can be used to set parameters for selecting only some of the instances or even specify exact instance, if no query parameters are specified packets will be traced on all available VPP instances.

<details open>
<summary><code>vpp-probe tracer --help</code></summary>

```sh
Trace packets from selected VPP instances during execution of custom command (usually ping), or for a specified duration.

Usage:
  vpp-probe tracer [flags] -- [command]

Aliases:
  tracer, trace

Examples:
  # Trace packets while running ping
  trace --env kube -q label=app=vpp -- ping 10.10.1.1

  # Trace packets for duration 3s
  trace --env kube -q label=app=vpp -d 5s

Flags:
  -d, --dur duration         Duration of tracing (ignored when command is defined) (default 5s)
  -h, --help                 help for tracer
      --numpackets uint      Number of packets to vpptrace per node (default 10000)
      --print                Print results from tracing to stdout
      --resultdir string     Directory to store raw VPP trace results (default "/tmp/vppprobe-traces")
      --tracenodes strings   List of traced nodes (default [af-packet-input,memif-input,tuntap-rx,virtio-input])
```

</details>

<details>
<summary>Example</summary>

```
$ vpp-probe -e kube -q name=vpp-vnf1 -q name=vpp-vnf2 -q name=vpp-vswitch tracer --print -- kubectl exec -it vpp-vswitch -- ping -c 1 192.168.23.2
INFO[0000] tracing started for 3/3 instances            
INFO[0000] running command: /bin/sh -c kubectl --context=kind-c2 exec -it vpp-vswitch -- ping -c 1 192.168.23.2 

Unable to use a TTY - input is not a terminal or the right kind of file
PING 192.168.23.2 (192.168.23.2) 56(84) bytes of data.
64 bytes from 192.168.23.2: icmp_seq=1 ttl=64 time=55.1 ms

--- 192.168.23.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 55.167/55.167/55.167/0.000 ms

INFO[0001] trace results retrieved from 3 instances     
INFO[0001] = instance vpp::kind-c2/default/vpp-vnf1     
INFO[0001]   traced: 4 packets                          
INFO[0001]   trace data saved to: /tmp/vppprobe-traces/vpptrace_vpp__kind-c2~default~vpp-vnf1_20210108t175534.txt 
INFO[0001] = instance vpp::kind-c2/default/vpp-vnf1: traced 4 packets 
# Packet 1 | ⏲  01:36:16.99700 | memif-input  ￫  memif1/2-output | took 11.724ms | nodes 5
 - memif-input
	memif: hw_if_index 1 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 1 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 2 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6c b9 40 00 40 01
 - memif1/2-output
	memif1/2
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e9c dscp CS0 ecn NON_ECN
	  fragment id 0x6cb9, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x8169
# Packet 2 | ⏲  01:36:17.03600 | memif-input  ￫  memif1/4-output | took 8.777ms | nodes 5
 - memif-input
	memif: hw_if_index 2 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 2 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 1 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 6d 00 00 40 01
 - memif1/4-output
	memif1/4
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5e8 dscp CS0 ecn NON_ECN
	  fragment id 0x256d
	ICMP echo_reply checksum 0x8969
# Packet 3 | ⏲  01:36:17.41300 | memif-input  ￫  memif1/2-output | took 11.422ms | nodes 5
 - memif-input
	memif: hw_if_index 1 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 1 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 2 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6d 01 40 00 40 01
 - memif1/2-output
	memif1/2
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e54 dscp CS0 ecn NON_ECN
	  fragment id 0x6d01, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x2e4c
# Packet 4 | ⏲  01:36:17.46100 | memif-input  ￫  memif1/4-output | took 24µs | nodes 5
 - memif-input
	memif: hw_if_index 2 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 2 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 1 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 84 00 00 40 01
 - memif1/4-output
	memif1/4
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5d1 dscp CS0 ecn NON_ECN
	  fragment id 0x2584
	ICMP echo_reply checksum 0x364c
INFO[0001] = instance vpp::kind-c2/default/vpp-vnf2     
INFO[0001]   traced: 2 packets                          
INFO[0001]   trace data saved to: /tmp/vppprobe-traces/vpptrace_vpp__kind-c2~default~vpp-vnf2_20210108t175534.txt 
INFO[0001] = instance vpp::kind-c2/default/vpp-vnf2: traced 2 packets 
# Packet 1 | ⏲  01:36:17.43000 | memif-input  ￫  memif1/1-output | took 18µs | nodes 5
 - memif-input
	memif: hw_if_index 1 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 1 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 2 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6d 01 40 00 40 01
 - memif1/1-output
	memif1/1
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e54 dscp CS0 ecn NON_ECN
	  fragment id 0x6d01, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x2e4c
# Packet 2 | ⏲  01:36:17.43500 | memif-input  ￫  memif1/3-output | took 7.92ms | nodes 5
 - memif-input
	memif: hw_if_index 2 next-index 4
	  slot: ring 0
 - ethernet-input
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 2 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 1 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 84 00 00 40 01
 - memif1/3-output
	memif1/3
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5d1 dscp CS0 ecn NON_ECN
	  fragment id 0x2584
	ICMP echo_reply checksum 0x364c
INFO[0001] = instance vpp::kind-c2/default/vpp-vswitch  
INFO[0001]   traced: 6 packets                          
INFO[0001]   trace data saved to: /tmp/vppprobe-traces/vpptrace_vpp__kind-c2~default~vpp-vswitch_20210108t175534.txt 
INFO[0001] = instance vpp::kind-c2/default/vpp-vswitch: traced 6 packets 
# Packet 1 | ⏲  01:36:17.41300 | virtio-input  ￫  memif1/4-output | took 75µs | nodes 5
 - virtio-input
	virtio: hw_if_index 2 next-index 4 vring 0 len 98
	  hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
 - ethernet-input
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 2 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 3 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6d 01 40 00 40 01
 - memif1/4-output
	memif1/4
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e54 dscp CS0 ecn NON_ECN
	  fragment id 0x6d01, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x2e4c
# Packet 2 | ⏲  01:36:17.42800 | memif-input  ￫  memif1/3-output | took 49µs | nodes 5
 - memif-input
	memif: hw_if_index 4 next-index 4
	  slot: ring 0
 - ethernet-input
	frame: flags 0x1, hw-if-index 4, sw-if-index 4
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 4 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 5 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6d 01 40 00 40 01
 - memif1/3-output
	memif1/3
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e54 dscp CS0 ecn NON_ECN
	  fragment id 0x6d01, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x2e4c
# Packet 3 | ⏲  01:36:17.44000 | memif-input  ￫  tap1-output | took 74µs | nodes 5
 - memif-input
	memif: hw_if_index 6 next-index 4
	  slot: ring 0
 - ethernet-input
	frame: flags 0x1, hw-if-index 6, sw-if-index 6
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
 - l2-input
	l2-input: sw_if_index 6 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57
 - l2-output
	l2-output: sw_if_index 1 dst 02:fe:1d:4d:e5:da src 02:fe:0b:d8:dc:57 data 08 00 45 00 00 54 6d 01 40 00 40 01
 - tap1-output
	tap1
	IP4: 02:fe:0b:d8:dc:57 -> 02:fe:1d:4d:e5:da
	ICMP: 192.168.23.1 -> 192.168.23.2
	  tos 0x00, ttl 64, length 84, checksum 0x1e54 dscp CS0 ecn NON_ECN
	  fragment id 0x6d01, flags DONT_FRAGMENT
	ICMP echo_request checksum 0x2e4c
# Packet 4 | ⏲  01:36:17.44200 | virtio-input  ￫  memif1/1-output | took 19µs | nodes 5
 - virtio-input
	virtio: hw_if_index 1 next-index 4 vring 0 len 98
	  hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
 - ethernet-input
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 1 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 6 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 84 00 00 40 01
 - memif1/1-output
	memif1/1
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5d1 dscp CS0 ecn NON_ECN
	  fragment id 0x2584
	ICMP echo_reply checksum 0x364c
# Packet 5 | ⏲  01:36:17.45100 | memif-input  ￫  memif1/2-output | took 52µs | nodes 5
 - memif-input
	memif: hw_if_index 5 next-index 4
	  slot: ring 0
 - ethernet-input
	frame: flags 0x1, hw-if-index 5, sw-if-index 5
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 5 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 4 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 84 00 00 40 01
 - memif1/2-output
	memif1/2
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5d1 dscp CS0 ecn NON_ECN
	  fragment id 0x2584
	ICMP echo_reply checksum 0x364c
# Packet 6 | ⏲  01:36:17.46400 | memif-input  ￫  tap0-output | took 22µs | nodes 5
 - memif-input
	memif: hw_if_index 3 next-index 4
	  slot: ring 0
 - ethernet-input
	frame: flags 0x1, hw-if-index 3, sw-if-index 3
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
 - l2-input
	l2-input: sw_if_index 3 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da
 - l2-output
	l2-output: sw_if_index 2 dst 02:fe:0b:d8:dc:57 src 02:fe:1d:4d:e5:da data 08 00 45 00 00 54 25 84 00 00 40 01
 - tap0-output
	tap0
	IP4: 02:fe:1d:4d:e5:da -> 02:fe:0b:d8:dc:57
	ICMP: 192.168.23.2 -> 192.168.23.1
	  tos 0x00, ttl 64, length 84, checksum 0xa5d1 dscp CS0 ecn NON_ECN
	  fragment id 0x2584
	ICMP echo_reply checksum 0x364c
```

</details>