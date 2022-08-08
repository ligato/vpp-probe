package agent

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-probe/pkg/exec"
)

func runAgentctlCmd(h exec.Interface, args ...string) ([]byte, error) {
	out, err := h.Command("agentctl", args...).Output()
	if err != nil {
		return nil, err
	}
	return out, err
}

func getInodeForFile(host exec.Interface, socket string) int {
	out, err := host.Command("ls", "-li", socket).Output()
	if err != nil {
		return 0
	}
	logrus.Tracef("file: %s", out)
	inode, _ := strconv.Atoi(string(bytes.Fields(out)[0]))
	return inode
}

func listInodes(host exec.Interface, socket string) int {
	out, err := host.Command("ls", "-li", socket).Output()
	if err != nil {
		return 0
	}
	logrus.Tracef("file: %s", out)
	inode, _ := strconv.Atoi(string(bytes.Fields(out)[0]))
	return inode
}

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
