package client

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp"
)

// Controller is a probe controller for VPP instances.
type Controller struct {
	providers []probe.Provider
	instances []*vpp.Instance
}

// NewController returns a new controller with LocalProvider as default provider.
func NewController() *Controller {
	return &Controller{}
}

// GetProviders returns all providers.
func (c *Controller) GetProviders() []probe.Provider {
	return c.providers
}

// AddProvider adss provider to the controller.
func (c *Controller) AddProvider(provider probe.Provider) error {
	for _, p := range c.providers {
		if p == provider {
			return fmt.Errorf("provider already added")
		}
	}
	c.providers = append(c.providers, provider)
	return nil
}

// Instances returns list of discovered VPP instances.
func (c *Controller) Instances() []*vpp.Instance {
	return c.instances
}

// DiscoverInstances discovers running VPP instances via probe provider and
// updates the list of instances with active instances from discovery.
func (c *Controller) DiscoverInstances(queryParams ...map[string]string) error {
	c.instances = nil

	for _, p := range c.providers {
		instances, err := c.discoverInstances(p, queryParams...)
		if err != nil {
			logrus.Warnf("provider %q discover error: %v", p.Name(), err)
			continue
		}
		c.instances = append(c.instances, instances...)
	}

	if len(c.instances) == 0 {
		return fmt.Errorf("no VPP instances available")
	}
	return nil
}

func (c *Controller) discoverInstances(provider probe.Provider, queryParams ...map[string]string) ([]*vpp.Instance, error) {
	handlers, err := provider.Query(queryParams...)
	if err != nil {
		return nil, err
	}

	var instances []*vpp.Instance
	for _, handler := range handlers {
		inst, err := newInstance(handler)
		if err != nil {
			logrus.Warnf("instance %v init error: %v", inst.ID(), err)
			continue
		}

		instances = append(instances, inst)
	}
	return instances, nil
}

func newInstance(handler probe.Handler) (*vpp.Instance, error) {
	inst, err := vpp.NewInstance(handler)
	if err != nil {
		logrus.Warnf("instance %v init error: %v", handler.ID(), err)
		return nil, err
	}

	return inst, nil
}
