package ui

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp"
	"go.ligato.io/vpp-probe/vpp/api"
)

var listCLIs = []string{
	"show version verbose",
	"show version cmdline",
	"show interface",
	"show interface addr",
	"show interface rx-placement",
	"show pci",
	"show hardware-interfaces",
	"show mode",
	"show node counters",
	"show runtime",
	"show plugins",
	"show api plugin",
	"show cli-sessions",
	"show api clients",
}

type VPP struct {
	*vpp.Instance

	ID         string
	Error      error
	Updating   bool
	LastUpdate time.Time

	Version string
	Pid     string
	Uptime  string

	Interfaces []*api.Interface
	Logs       []string
	Stats      []string
	Extra      []string
	CLIs       map[string]string
}

func newVPP(instance *vpp.Instance) *VPP {
	info := instance.VppInfo()
	return &VPP{
		Instance:   instance,
		ID:         instance.ID(),
		LastUpdate: time.Now(),
		Version:    info.Build.Version,
		Pid:        fmt.Sprint(info.System.Pid),
	}
}

func (i *VPP) String() string {
	return i.ID
}

func vppList(instances []*vpp.Instance) []*VPP {
	var vpps []*VPP
	for _, handler := range instances {
		v := newVPP(handler)
		vpps = append(vpps, v)
	}
	return vpps
}

func (a *App) update(index int) {
	instance := a.instances[index]

	log := logrus.WithFields(map[string]interface{}{
		"instance": instance.ID,
	})

	reload := func(f func()) {
		a.QueueUpdateDraw(func() {
			f()
			a.refreshInstance(index)
		})
	}

	reload(func() {
		instance.Updating = true
	})

	log.Debugf("updating instance")

	go func() {
		{
			uptime, err := instance.GetUptime()
			reload(func() {
				if err != nil {
					instance.Uptime = err.Error()
					log.Errorf("GetUptime failed: %v", err)
				} else {
					instance.Uptime = uptime.String()
				}
			})
		}

		{
			list, err := instance.ListInterfaces()
			reload(func() {
				if err != nil {
					instance.Error = err
					log.Errorf("ListInterfaces failed: %v", err)
				} else {
					instance.Interfaces = list
				}
			})
		}

		{
			logs, err := instance.DumpLogs()
			reload(func() {
				if err != nil {
					instance.Error = err
					log.Errorf("DumpLogs failed: %v", err)
				} else {
					instance.Logs = logs
				}
			})
		}

		{
			stats, err := instance.ListStats()
			reload(func() {
				if err != nil {
					instance.Error = err
					log.Errorf("ListStats failed: %v", err)
				} else {
					instance.Stats = stats
				}
			})
		}

		var clis = map[string]string{}
		for _, cmd := range listCLIs {
			command := cmd
			output, err := instance.RunCli(command)
			reload(func() {
				if err != nil {
					clis[command] = err.Error()
					instance.Error = err
					log.Errorf("RunCli failed: %v", err)
				} else {
					clis[command] = output
				}
				instance.CLIs = clis
			})
		}

		reload(func() {
			instance.LastUpdate = time.Now()
			instance.Updating = false
		})
	}()
}
