package termui

import (
	"github.com/gdamore/tcell"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/controller"
	"go.ligato.io/vpp-probe/vpp"
)

// App is a terminal UI app,
type App struct {
	*tview.Application

	instanceList   *InstanceList
	infoPanel      *InfoPanel
	interfaceTable *InterfaceTable
	logPanel       *LogPanel
	statusBar      *StatusBar

	focuses []tview.Primitive

	probectl  *controller.Controller
	instances []*Instance
}

func NewApp(probectl *controller.Controller) *App {
	a := &App{
		Application: tview.NewApplication(),
		probectl:    probectl,
	}

	a.instanceList = NewInstanceList()
	a.infoPanel = NewInfoPanel()
	a.interfaceTable = NewInterfaceTable()
	a.logPanel = NewLogPanel()
	a.statusBar = NewStatusBar()

	a.focuses = []tview.Primitive{
		a.instanceList,
		a.infoPanel,
		a.interfaceTable,
		a.logPanel,
	}

	a.statusBar.SetKeyBinds([]KeyBind{
		{Key: "Enter", Action: "select instance"},
		{Key: "Tab", Action: "switch panel"},
		{Key: "q", Action: "quit"},
	})

	a.instanceList.SetSelectedFunc(func(index int, s string, s2 string, r rune) {
		go a.update(index)
		a.showInstance(index)
	})
	a.instanceList.SetChangedFunc(func(index int, text string, text2 string, shortcut rune) {
		a.showInstance(index)
	})
	a.interfaceTable.SetDoneFunc(func(key tcell.Key) {
		a.SetFocus(a.instanceList)
	})

	logrus.SetOutput(tview.ANSIWriter(a.logPanel))

	a.SetInputCapture(a.onInput)
	a.SetRoot(a.flexLayout(), true)

	a.setInstances(a.probectl.Instances())

	return a
}

func (a *App) flexLayout() *tview.Flex {
	flexInstanceRow := tview.NewFlex()
	flexInstanceRow.SetDirection(tview.FlexColumn)
	flexInstanceRow.AddItem(a.instanceList, 0, 1, true)
	flexInstanceRow.AddItem(a.infoPanel, 0, 1, true)

	flexMain := tview.NewFlex()
	flexMain.SetDirection(tview.FlexRow)
	flexMain.AddItem(flexInstanceRow, 0, 1, true)
	flexMain.AddItem(a.interfaceTable, 0, 3, true)
	flexMain.AddItem(a.logPanel, 0, 1, true)
	flexMain.AddItem(a.statusBar, 1, 0, false)

	return flexMain
}

func (a *App) setInstances(instances []*vpp.Instance) {
	a.instances = nil
	for _, instance := range instances {
		info := instance.VersionInfo()
		inst := &Instance{
			ID:      instance.ID(),
			Version: info.Version,
			Pid:     info.Pid,
		}
		a.instances = append(a.instances, inst)
	}
	a.instanceList.SetInstances(a.instances)
}

func (a *App) showInstance(index int) {
	instance := a.instances[index]

	a.infoPanel.SetInstance(instance)
	a.interfaceTable.SetInterfaces(instance.Interfaces)
	a.logPanel.SetLogs(instance.Logs)

	//a.SetFocus(a.interfaceTable)
}

func (a *App) onInput(e *tcell.EventKey) *tcell.EventKey {
	switch e.Key() {
	case tcell.KeyCtrlC:
		a.Stop()
	case tcell.KeyRune:
		switch e.Rune() {
		case 'q':
			a.Stop()
		}
	case tcell.KeyTab:
		a.focusNext()
		return nil
	}
	return e
}

func (a *App) focusNext() int {
	for i, f := range a.focuses {
		if f.GetFocusable().HasFocus() {
			idx := (i + 1) % len(a.focuses)
			a.SetFocus(a.focuses[idx])
			return idx
		}
	}
	return 0
}
