package local

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mitchellh/go-ps"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

// Provider manages locally running instances.
type Provider struct {
	Config HandlerConfig
}

func NewProvider(config HandlerConfig) *Provider {
	return &Provider{
		Config: config,
	}
}

func (p *Provider) Env() string {
	return providers.Local
}

func (p *Provider) Name() string {
	return "local"
}

func (p *Provider) Query(params ...map[string]string) ([]probe.Handler, error) {
	procs, err := ps.Processes()
	if err != nil {
		return nil, nil
	}

	var handlers []probe.Handler
	for _, proc := range procs {
		executable := strings.ToLower(proc.Executable())
		if !strings.Contains(executable, "vpp") {
			continue
		}
		if !isVppProcess(proc.Pid()) {
			continue
		}

		logrus.Infof("found local vpp process (pid %d)", proc.Pid())

		h := NewHandler(proc.Pid(), p.Config)

		handlers = append(handlers, h)
	}

	if len(handlers) == 0 {
		return nil, fmt.Errorf("no instances found")
	}
	return handlers, nil
}

func isVppProcess(pid int) bool {
	b, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		logrus.Debugf("read file failed: %v", err)
		return false
	}
	if !strings.Contains(string(b), "vpp_main") {
		return false
	}
	const cgroupPids = "pids"
	cgroup, err := getProcessCgroup(pid, cgroupPids)
	if err != nil {
		logrus.Debugf("getCgroup failed: %v", err)
		return false
	}
	if cgroup != getSelfCgroup(cgroupPids) && strings.Contains(cgroup, "docker") {
		return false
	}
	return true
}

func getProcessCgroup(pid int, typ string) (string, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	cgroup, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range bytes.Split(cgroup, []byte("\n")) {
		parts := bytes.SplitN(line, []byte(":"), 3)
		partTyp := string(parts[1])
		partVal := string(parts[2])
		if partTyp == typ {
			return partVal, nil
		}
	}
	return "", fmt.Errorf("cgroup %q not found", typ)
}

func getSelfCgroup(typ string) string {
	c, _ := getProcessCgroup(os.Getpid(), typ)
	return c
}
