package client

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp"
)

// Client is a client for managing providers and instances.
type Client struct {
	providers []providers.Provider
	instances []*vpp.Instance
}

// NewClient returns a new client using given options.
func NewClient(opt ...Opt) (*Client, error) {
	c := &Client{}
	for _, o := range opt {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Close releases used resources.
func (c *Client) Close() error {
	// TODO: close connections gracefully and free resources
	return nil
}

// GetProviders returns all providers.
func (c *Client) GetProviders() []providers.Provider {
	return c.providers
}

// Instances returns list of VPP instances.
func (c *Client) Instances() []*vpp.Instance {
	return c.instances
}

// AddProvider adds provider to the client or returns error if the provided
// was already added.
func (c *Client) AddProvider(provider providers.Provider) error {
	if provider == nil {
		panic("provider is nil")
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

	var instanceList []*vpp.Instance

	instanceChan := make(chan []*vpp.Instance)
	for _, p := range c.providers {
		go func(provider providers.Provider) {
			instances, err := queryInstances(provider, queryParams...)
			if err != nil {
				logrus.Warnf("provider %q discover error: %v", provider.Name(), err)
			}
			instanceChan <- instances
		}(p)
	}

	for range c.providers {
		instances := <-instanceChan
		if len(instances) > 0 {
			instanceList = append(instanceList, instances...)
		}
	}

	c.instances = instanceList
	if len(c.instances) == 0 {
		return fmt.Errorf("no instances discovered")
	}

	return nil
}

func queryInstances(provider providers.Provider, queryParams ...map[string]string) ([]*vpp.Instance, error) {
	handlers, err := provider.Query(queryParams...)
	if err != nil {
		return nil, err
	}

	var instances []*vpp.Instance
	for _, handler := range handlers {
		inst, err := vpp.NewInstance(handler)
		if err != nil {
			logrus.WithField("instance", handler.ID()).
				Debugf("vpp instance init failed: %v", err)
			continue
		}

		instances = append(instances, inst)
	}

	return instances, nil
}
