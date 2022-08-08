package topology

import (
	"fmt"

	"go.ligato.io/vpp-probe/vpp"
)

// Info groups together a topology information.
type Info struct {
	Networks    []Network
	Connections []Connection
}

// NetworkType is a type of network found in a topology.
type NetworkType string

const (
	UndefinedNetwork NetworkType = ""
	// UserNetwork is a network in the user space (SDN)
	UserNetwork = "user"
	// KernelNetwork is a network in kernel space (Linux networking)
	KernelNetwork = "kernel"
)

// Network defines a particular network in topology.
type Network struct {
	// Instance is the name of instance this network is part of.
	Instance string
	// Type is the type of this network.
	Type NetworkType
	// Namespace is the name of namespace this network belongs to.
	// If empty, default network is assumed.
	Namespace string
}

type EndpointType string

const (
	UnknownEndpointType EndpointType = ""
	InterfaceEndpoint                = "interface"
	FileEndpoint                     = "file"
)

func newVppNetwork(instance *vpp.Instance) Network {
	return Network{
		Type:     UserNetwork,
		Instance: instance.ID(),
	}
}

func newLinuxNetwork(instance *vpp.Instance, namespace string) Network {
	return Network{
		Type:      KernelNetwork,
		Instance:  instance.ID(),
		Namespace: namespace,
	}
}

// Endpoint defines a communication endpoint in a network.
type Endpoint struct {
	Network
	Interface string
	Kind      EndpointType
	Metadata  map[string]string
}

func (e *Endpoint) addMetadata(key, value string) *Endpoint {
	if e.Metadata == nil {
		e.Metadata = map[string]string{}
	}
	e.Metadata[key] = value
	return e
}

// Connection defines a connection between two endpoints.
// It is represented as an edge.
type Connection struct {
	Source      Endpoint
	Destination Endpoint
	Metadata    map[string]string
}

func (c Connection) String() string {
	src := c.Source.Interface
	dst := c.Destination.Interface
	if c.Source.Type == KernelNetwork {
		src = fmt.Sprintf("LINUX-%s", src)
	}
	if c.Destination.Type == KernelNetwork {
		dst = fmt.Sprintf("LINUX-%s", dst)
	}
	if c.Source.Namespace != "" {
		src += fmt.Sprintf("-NS-%s", c.Source.Namespace)
	}
	if c.Destination.Namespace != "" {
		dst += fmt.Sprintf("-NS-%s", c.Destination.Namespace)
	}
	src = fmt.Sprintf("%v/%v", c.Source.Instance, src)
	dst = fmt.Sprintf("%v/%v", c.Destination.Instance, dst)
	return fmt.Sprintf("%q -> %q", src, dst)
}

func (c *Connection) addMetadata(key, value string) *Connection {
	if c.Metadata == nil {
		c.Metadata = map[string]string{}
	}
	c.Metadata[key] = value
	return c
}
