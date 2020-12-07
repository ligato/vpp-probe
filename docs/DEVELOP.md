# Developer Guide

This guide contains information for developers.
 
## Overview

The core components of vpp-probe are: 

**Environment**
- defines environment where VPP is running

**Controller**
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

### Environment Types

* Local
  - Host
* Remote
  - Kubernetes
  - Docker

### VPP Access

* CLI
  - via exec `vppctl` cmd
  - via exec `agentctl vpp cli` cmd (vpp-agent only) 
  - via binapi `vpe.CliInband` req (requires Binary API)
  
* Binary API
  - direct to socket (local only)
  - via proxy (vpp-agent or standalone GoVPP proxy)
  
* Stats API
  - direct to socket+shm (local only)
  - via proxy (vpp-agent or standalone GoVPP proxy)

