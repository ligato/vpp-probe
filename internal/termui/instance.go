package termui

import (
	"strings"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/vpp/types"
)

type Instance struct {
	ID    string
	Error error

	Version string
	Pid     int
	Clock   string

	Interfaces []*types.Interface
	Logs       []string
}

func (a *App) update(index int) {
	instance := a.instances[index]
	vppInstance := a.probectl.Instances()[index]

	reload := func(f func()) {
		a.QueueUpdateDraw(func() {
			if f != nil {
				f()
			}
			if a.instanceList.GetCurrentItem() == index {
				a.showInstance(index)
			}
		})
	}

	list, err := vppInstance.ListInterfaces()
	reload(func() {
		if err != nil {
			instance.Error = err
			logrus.Error(err)
			return
		} else {
			instance.Interfaces = list
		}
	})

	clock, err := vppInstance.GetClock()
	reload(func() {
		if err != nil {
			instance.Error = err
			logrus.Error(err)
			return
		} else {
			instance.Clock = strings.TrimSpace(clock)
		}
	})

	logs, err := vppInstance.DumpLogs()
	reload(func() {
		if err != nil {
			instance.Error = err
			logrus.Error(err)
			return
		} else {
			instance.Logs = logs
		}
	})
}
