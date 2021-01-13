package client

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers/local"
	"go.ligato.io/vpp-probe/vpp"
)

// Client is a client for managing providers and instances.
type Client struct {
	providers []probe.Provider
	instances []*vpp.Instance
}

// NewClient returns a new client with default options.
func NewClient() *Client {
	return &Client{}
}

// GetProviders returns all probe providers.
func (c *Client) GetProviders() []probe.Provider {
	return c.providers
}

// Instances returns list of VPP instances.
func (c *Client) Instances() []*vpp.Instance {
	return c.instances
}

// AddProvider adds provider to the client or returns error if the provided
// was already added. In case the provider is nil, local provider with default
// config is used.
func (c *Client) AddProvider(provider probe.Provider) error {
	if provider == nil {
		provider = local.NewProvider(local.DefaultConfig())
	}

	// check duplicate
	for _, p := range c.providers {
		if p == provider {
			return fmt.Errorf("provider '%v' already added", p)
		}
	}

	c.providers = append(c.providers, provider)

	return nil
}

// DiscoverInstances discovers running VPP instances via probe provider and
// updates the list of instances with active instances from discovery.
func (c *Client) DiscoverInstances(queryParams ...map[string]string) error {
	if len(c.providers) == 0 {
		return fmt.Errorf("no providers available")
	}

	// reset list
	c.instances = []*vpp.Instance{}

	for _, p := range c.providers {
		instances, err := discoverInstances(p, queryParams...)
		if err != nil {
			logrus.Warnf("provider %q discover error: %v", p.Name(), err)
			continue
		}
		c.instances = append(c.instances, instances...)
	}

	if len(c.instances) == 0 {
		return fmt.Errorf("no instances discovered")
	}
	return nil
}

func discoverInstances(provider probe.Provider, queryParams ...map[string]string) ([]*vpp.Instance, error) {
	handlers, err := provider.Query(queryParams...)
	if err != nil {
		return nil, err
	}

	var instances []*vpp.Instance
	for _, handler := range handlers {
		inst, err := vpp.NewInstance(handler)
		if err != nil {
			logrus.Warnf("vpp instance %v init failed: %v", handler.ID(), err)
			continue
		}

		instances = append(instances, inst)
	}

	return instances, nil
}
