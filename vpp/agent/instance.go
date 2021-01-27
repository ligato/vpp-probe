package agent

import (
	"fmt"

	"go.ligato.io/vpp-probe/probe"
)

type Instance struct {
	probe.Handler `json:"Handler"`

	cli probe.CliExecutor

	Config  *Config
	Version string
}

func NewInstance(handler probe.Handler) (*Instance, error) {
	cli, err := handler.GetCLI()
	if err != nil {
		return nil, fmt.Errorf("CLI handler error: %w", err)
	}
	instance := &Instance{
		Handler: handler,
		cli:     cli,
	}
	if err := instance.UpdateInstanceInfo(); err != nil {
		return nil, err
	}
	return instance, nil
}

func (instance *Instance) UpdateInstanceInfo() (err error) {
	instance.Config, err = retrieveConfig(instance.Handler)
	if err != nil {
		return fmt.Errorf("retrieving config failed: %w", err)
	}
	return nil
}
