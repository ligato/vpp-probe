// Package agent handles VPP-Agent instance data.
package agent

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-probe/pkg/log"

	"go.ligato.io/vpp-probe/probe"
)

type Instance struct {
	handler probe.Handler

	Config *Config
	Info   *Info
}

func NewInstance(handler probe.Handler) (*Instance, error) {
	instance := &Instance{
		handler: handler,
	}
	return instance, instance.Init()
}

func (instance *Instance) Init() (err error) {
	instance.Info, err = RetrieveInfo(instance.handler)
	if err != nil {
		return fmt.Errorf("retrieving status failed: %w", err)
	}

	return nil
}

func (instance *Instance) UpdateInstanceInfo() (err error) {
	defer log.TraceElapsed(logrus.WithFields(map[string]interface{}{
		"instance": instance.handler.ID(),
	}), "updating instance info")()

	instance.Config, err = RetrieveConfig(instance.handler)
	if err != nil {
		return fmt.Errorf("retrieving config failed: %w", err)
	}

	return nil
}

type Info struct {
	Status struct {
		BuildVersion string `json:"build_version"`
		BuildDate    string `json:"build_date"`
	}
}

func RetrieveInfo(handler probe.Handler) (*Info, error) {
	log := logrus.WithFields(map[string]interface{}{
		"instance": handler.ID(),
	})

	out, err := runAgentctlCmd(handler, "status", "-f", "json")
	if err != nil {
		return nil, err
	}

	var info *Info
	if err := json.Unmarshal(out, &info); err != nil {
		log.Tracef("status json data: %s", out)
		return nil, fmt.Errorf("unmarshaling failed: %w", err)
	}

	return info, nil
}
