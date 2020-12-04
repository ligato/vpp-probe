package controller

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp"
)

// TODO:
//  - run instance discovery in intervals
//  - consider using list of providers instead of one
//  - check if instances are still running periodically
//  - stream events (new instance, instance unreachable..) via channel

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
func (c *Controller) DiscoverInstances(queries ...string) error {
	queryParams := parseQueries(queries)

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
		instance := &probe.Probe{
			Location: handler.ID(),
			Provider: provider.Name(),
			Handler:  handler,
		}

		inst, err := vpp.NewInstance(instance)
		if err != nil {
			logrus.Warnf("instance %v init error: %v", instance.Location, err)
			continue
		}

		instances = append(instances, inst)
	}
	return instances, nil
}

func parseQueries(queries []string) []map[string]string {
	var queryParams []map[string]string
	for _, q := range queries {
		params := strings.Split(q, ",")
		for _, p := range params {
			qp := map[string]string{}
			if i := strings.Index(p, "="); i > 0 {
				key := p[:i]
				val := p[i+1:]
				qp[key] = val
			} else {
				qp[p] = ""
			}
			queryParams = append(queryParams, qp)
		}
	}
	return queryParams
}
