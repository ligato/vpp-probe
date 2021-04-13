# Developing vpp-probe

This guide contains information for developers.
 
## Overview

The core components of vpp-probe are: 

**Environment**
- defines environment where VPP is running

**Client**
- handles setup of running environment

**Provider**
- searches for VPP instances
- initializes and manages access to VPP instances

**Instance**
- provides a common interface for accessing VPP
  - CLI
  - Stats
  - Binary API
- provides a common interface for executing commands
- can have different implementation for each env

**VPP Handler**
- represents running VPP instance
- uses instance handler for interacting with VPP
- negotiates the preferred access to VPP
- provides API for
    - retrieving basic info
    - listing interfaces
    - getting metrics
    - watching events

## Providers

### Runtime Environment

VPP instance local or remote  

* Local
  - Host
* Remote
  - Kubernetes
  - Docker

## Instance

VPP instance manages a running VPP and provides common API for the VPP data.

### VPP Data & API

VPP data is accessed in various ways depending on the VPP configuration and current availability.

**VPP CLI**
- by running `vppctl` program
- calling RPC `vpe.CliInband` (VPP binary API must be available)
- via agent API (requires vpp-agent)

**VPP Binary API**
- direct to unix socket `/run/vpp/api.sock` (local env only)
- via proxy (vpp-agent or standalone GoVPP proxy)
  
**VPP Stats API**
- direct to shared memory (local env only)
- via proxy (vpp-agent or standalone GoVPP proxy)

|API| Access | Description | Local Env | Kube Env | Docker Env |
|---|---|---|---|---|---|
|VPP CLI|by running `vppctl` program| |direct|pod exec|conainer exec|
|-|calling RPC `vpe.CliInband`| |direct|pod exec|conainer exec|
|-|by running `vppctl` program| |direct|pod exec|conainer exec|