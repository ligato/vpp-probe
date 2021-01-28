package agent

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-probe/probe"
)

type Instance struct {
	probe.Handler `json:"Handler"`

	Config *Config
}

func NewInstance(handler probe.Handler) (*Instance, error) {
	instance := &Instance{
		Handler: handler,
	}
	if err := instance.Init(); err != nil {
		return nil, err
	}
	return instance, nil
}

func (instance *Instance) Init() error {
	out, err := runAgentctlCmd(instance, "status")
	if err != nil {
		return err
	}

	logrus.Debugf("agent status:\n%s", out)

	return nil
}

func (instance *Instance) UpdateInstanceInfo() (err error) {
	instance.Config, err = RetrieveConfig(instance.Handler)
	if err != nil {
		return fmt.Errorf("retrieving config failed: %w", err)
	}

	return nil
}
