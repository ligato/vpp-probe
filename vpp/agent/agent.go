// Package agent handles VPP-Agent instance data.
package agent

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
)

type Instance struct {
	handler probe.Handler

	Config *Config
}

func NewInstance(handler probe.Handler) (*Instance, error) {
	instance := &Instance{
		handler: handler,
	}
	return instance, instance.Init()
}

func (instance *Instance) Init() error {
	out, err := runAgentctlCmd(instance.handler, "status")
	if err != nil {
		return err
	}

	logrus.Debugf("agent status:\n%s", out)

	return nil
}

func (instance *Instance) UpdateInstanceInfo() (err error) {
	instance.Config, err = RetrieveConfig(instance.handler)
	if err != nil {
		return fmt.Errorf("retrieving config failed: %w", err)
	}

	return nil
}
