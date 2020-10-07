package controller

import (
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/probe/localprobe"
	"go.ligato.io/vpp-probe/vpp"
)

var DefaultProvider = new(localprobe.Provider)

// Controller is a probe controller for VPP instances.
type Controller struct {
	// TODO: consider using list of providers?
	provider     probe.Provider
	vppInstances []*vpp.Instance
}

// NewController returns a new controller with provider set to DefaultProvider.
func NewController() *Controller {
	return &Controller{
		provider: DefaultProvider,
	}
}

// SetProvider sets the probe provider and runs DiscoverInstances.
func (probe *Controller) SetProvider(provider probe.Provider) error {
	probe.provider = provider
	return probe.DiscoverInstances()
}

// DiscoverInstances discovers running VPP instances via probe provider and
// updates the list of instances with active instances from discovery.
func (probe *Controller) DiscoverInstances() error {
	instances, err := probe.provider.Discover()
	if err != nil {
		return err
	}

	probe.vppInstances = nil
	for _, instance := range instances {
		inst := vpp.NewInstance(instance)

		if err := inst.Init(); err != nil {
			logrus.Warnf("instance %v init error: %v", instance, err)
			continue
		}

		probe.addVppInstance(inst)
	}
	return nil
}

// Instances returns list of discovered VPP instances.
func (probe *Controller) Instances() []*vpp.Instance {
	return probe.vppInstances
}

func (probe *Controller) addVppInstance(vpp *vpp.Instance) {
	probe.vppInstances = append(probe.vppInstances, vpp)
}
