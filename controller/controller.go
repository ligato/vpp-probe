package controller

import (
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/vpp"
)

// Probe is a controller for accessing VPP instances.
type Controller struct {
	provider     probe.Provider
	vppInstances []*vpp.Instance
}

func NewController() *Controller {
	return &Controller{
		provider: probe.DefaultProvider,
	}
}

func (probe *Controller) SetProvider(provider probe.Provider) error {
	probe.provider = provider
	return probe.DiscoverInstances()
}

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

func (probe *Controller) Instances() []*vpp.Instance {
	return probe.vppInstances
}

func (probe *Controller) addVppInstance(vpp *vpp.Instance) {
	probe.vppInstances = append(probe.vppInstances, vpp)
}
