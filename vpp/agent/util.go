package agent

import (
	"fmt"
	"strconv"

	"go.ligato.io/vpp-probe/pkg/exec"
)

func toInt(v interface{}) int {
	s := fmt.Sprint(v)
	idx, _ := strconv.Atoi(s)
	return idx
}

func toBool(v interface{}) bool {
	s := fmt.Sprint(v)
	idx, _ := strconv.ParseBool(s)
	return idx
}

func runAgentctlCmd(h exec.Interface, args ...string) ([]byte, error) {
	out, err := h.Command("agentctl", args...).Output()
	if err != nil {
		return nil, err
	}
	return out, err
}
