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

func NewProvider() (*Provider, error) {
	provider := &Provider{
		Config: DefaultConfig(),
	}
	return provider, nil
}

func (p *Provider) Env() probe.Env {
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

		handler := NewHandler(proc.Pid(), p.Config)
		handlers = append(handlers, handler)
	}

	if len(handlers) == 0 {
		return nil, fmt.Errorf("no instances found")
	}
	return handlers, nil
}

func (p *Provider) Search(query ...interface{}) ([]*probe.Instance, error) {
	var instances []*probe.Instance

	procs, err := ps.Processes()
	if err != nil {
		return nil, nil
	}
	for _, proc := range procs {
		executable := strings.ToLower(proc.Executable())
		if !strings.Contains(executable, "vpp") {
			continue
		}
		if !isVppProcess(proc.Pid()) {
			continue
		}
		logrus.Infof("found local vpp process (pid %d)", proc.Pid())
		handler := NewHandler(proc.Pid(), p.Config)
		instance := &probe.Instance{
			//Location: handler.ID(),
			Provider: p.Name(),
			Handler:  handler,
		}
		instances = append(instances, instance)
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no instances found")
	}

	return instances, nil
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
	cgroup, err := getCgroup(pid, cgroupPids)
	if err != nil {
		logrus.Debugf("getCgroup failed: %v", err)
		return false
	}
	if cgroup != getCgroupSelf(cgroupPids) && strings.Contains(cgroup, "docker") {
		return false
	}
	return true
}

func getCgroup(pid int, typ string) (string, error) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	cgroup, err := ioutil.ReadFile(cgroupPath)
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

func getCgroupSelf(typ string) string {
	c, _ := getCgroup(os.Getpid(), typ)
	return c
}
