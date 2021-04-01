package topology

import (
	"fmt"

	"go.ligato.io/vpp-probe/vpp"
)

type Info struct {
	Networks    []Network
	Connections []*Connection
}

type NetworkType string

const (
	UnknownNetwork NetworkType = ""
	VppNetwork                 = "vpp"
	LinuxNetwork               = "linux"
)

type Network struct {
	Type      NetworkType
	Instance  string
	Namespace string
}

func newVppNetwork(instance *vpp.Instance) Network {
	return Network{
		Type:     VppNetwork,
		Instance: instance.ID(),
	}
}

func newLinuxNetwork(instance *vpp.Instance, namespace string) Network {
	return Network{
		Type:      LinuxNetwork,
		Instance:  instance.ID(),
		Namespace: namespace,
	}
}

// Endpoint defines a communication endpoint in a network.
type Endpoint struct {
	Network
	Interface string
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
	if c.Source.Type == LinuxNetwork {
		src = fmt.Sprintf("LINUX-%s", src)
	}
	if c.Destination.Type == LinuxNetwork {
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
