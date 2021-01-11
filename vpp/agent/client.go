package agent

import (
	"encoding/json"

	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"

	"go.ligato.io/vpp-probe/probe"
)

type KVData struct {
	Key      string
	Metadata map[string]interface{} `json:",omitempty"`
	Origin   api.ValueOrigin
	Value    json.RawMessage
}

func runAgentctlCmd(host probe.Host, args ...string) ([]byte, error) {
	dump, err := host.ExecCmd("agentctl", args...)
	if err != nil {
		return nil, err
	}
	return []byte(dump), err
}
