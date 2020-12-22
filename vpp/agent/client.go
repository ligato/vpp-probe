package agent

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"

	"go.ligato.io/vpp-probe/probe"
)

type KVData struct {
	Key      string
	Metadata map[string]interface{} `json:",omitempty"`
	Origin   api.ValueOrigin
	Value    interface{}
}

func agentctlCmd(handler probe.Host, args ...string) ([]byte, error) {
	dump, err := handler.ExecCmd("agentctl", args...)
	if err != nil {
		return nil, err
	}
	return []byte(dump), err
}

func listModelData(handler probe.Host, model *models.KnownModel, v interface{}) error {
	dump, err := agentctlCmd(handler, "dump", "-f ", "json", model.Name())
	if err != nil {
		return fmt.Errorf("dumping model %s (json) failed: %w", model.Name(), err)
	}
	logrus.Debugf("dumped model %s (%d bytes)", model.Name(), len(dump))
	if err := json.Unmarshal(dump, v); err != nil {
		return fmt.Errorf("unmarshaling model %s dump (json) failed: %w", model.Name(), err)
	}
	return nil
}
