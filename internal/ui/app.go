package ui

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/go-stack/stack"
	"github.com/sirupsen/logrus"
	tview "gitlab.com/tslocum/cview"

	"go.ligato.io/vpp-probe/probe/controller"
)

// App is a terminal UI app,
type App struct {
	*tview.Application

	ctx    context.Context
	cancel func()
	wg     sync.WaitGroup

	probectl  *controller.Controller
	instances []*VPP

	navbar         *Navbar
	instanceList   *InstanceList
	infoPanel      *InfoPanel
	pagesPanel     *PagesPanel
	interfaceTable *InterfaceTable

	statusBar *StatusBar
	rootFlex  *tview.Flex
	focusMgr  *tview.FocusManager
	logFile   *os.File
}

func NewApp(probectl *controller.Controller) *App {
	a := &App{
		Application: tview.NewApplication(),
		probectl:    probectl,
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.initLog()

	a.Application.EnableMouse(true)

	a.navbar = NewNavbar()
	a.instanceList = NewInstanceList()
	a.infoPanel = NewInfoPanel()
	a.pagesPanel = NewPagesPanel()
	a.interfaceTable = NewInterfaceTable()
	a.statusBar = NewStatusBar()

	a.Application.SetAfterFocusFunc(a.afterFocus)

	a.focusMgr = tview.NewFocusManager(a.SetFocus)
	a.focusMgr.SetWrapAround(true)
	a.focusMgr.Add([]tview.Primitive{
		a.instanceList,
		a.interfaceTable,
		a.pagesPanel,
	}...)

	a.SetInputCapture(a.onInput)

	a.instanceList.SetSelectedFunc(func(i int, item *tview.ListItem) {
		instance := a.instances[i]
		logrus.Debugf("selected instance %v", instance)
		a.showInstance(instance)
		if instance.Updating != true {
			a.update(i)
		}
	})
	a.instanceList.SetChangedFunc(func(i int, item *tview.ListItem) {
		a.showInstance(a.instances[i])
	})
	a.interfaceTable.SetDoneFunc(func(key tcell.Key) {
		a.SetFocus(a.instanceList)
	})

	// a.initSignals()

	a.wg.Add(1)
	go a.periodicRefresh(time.Second)

	return a
}

func (a *App) initLog() {
	/*a.logPanel.SetVisible(false)
	a.logPanel.SetBorder(false)*/
	var err error
	a.logFile, err = os.OpenFile("vpp-probe.log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Fatal(err)
	}
	//logrus.SetOutput(io.MultiWriter(a.logFile, tview.ANSIWriter(a.logPanel)))
	logrus.SetOutput(a.logFile)
}
func (a *App) closeLog() {
	logrus.SetOutput(os.Stderr)
	/*if a.logFile != nil {
		if err := a.logFile.Close(); err != nil {
			panic(err)
		}
		a.logFile = nil
	}*/
}

func (a *App) Stop() {
	a.cancel()
	a.wg.Wait()
	a.Application.Stop()
	a.closeLog()
}

func (a *App) Run() error {
	if err := a.Application.Run(); err != nil {
		return err
	}
	return nil
}

func (a *App) flexLayout() *tview.Flex {
	flexMain := tview.NewFlex()
	flexMain.SetDirection(tview.FlexRow)

	flexInstanceRow := tview.NewFlex()
	flexInstanceRow.SetDirection(tview.FlexColumn)
	flexInstanceRow.AddItem(a.instanceList, 0, 3, true)
	flexInstanceRow.AddItem(a.infoPanel, 0, 4, false)

	flexMain.AddItem(a.navbar, 5, 0, false)
	flexMain.AddItem(flexInstanceRow, 12, 0, true)
	flexMain.AddItem(a.interfaceTable, 0, 3, true)
	flexMain.AddItem(a.pagesPanel, 0, 3, true)
	flexMain.AddItem(a.statusBar, 1, 0, false)

	return flexMain
}

func (a *App) initSignals() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig,
		syscall.SIGTERM,
		syscall.SIGABRT,
		syscall.SIGINT,
		syscall.SIGHUP,
		syscall.SIGQUIT,
	)
	go func(sig chan os.Signal) {
		s := <-sig
		logrus.Infof("received signal: %v", s)
		if s == syscall.SIGHUP {
			os.Exit(0)
		} else if s == syscall.SIGINT {
			a.Suspend(func() {
				fmt.Fprintln(os.Stderr, stack.Trace().String())
			})
		}
	}(sig)
}

func (a *App) RunDiscovery(queryParams ...string) {
	a.instances = nil
	a.instanceList.Clear()

	modalText := fmt.Sprintf("Discovering instances..\n\n%d providers\n\n%v", len(a.probectl.GetProviders()), a.probectl.GetProviders())

	modal := tview.NewModal()
	modal.SetTitle("Discovering instances..")
	modal.SetText(modalText)
	modal.AddButtons([]string{"Quit"})
	modal.SetBackgroundColor(tcell.ColorDarkSlateBlue)
	modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
		if buttonLabel == "Quit" {
			a.Stop()
		}
	})
	a.SetRoot(modal, false)

	done := make(chan error, 1)

	go func() {
		err := a.probectl.DiscoverInstances(queryParams...)
		done <- err
		close(done)
	}()

	text := modalText

	go func() {
		for {
			select {
			case <-time.After(time.Second):
				text = text + "."
				a.QueueUpdateDraw(func() {
					modal.SetText(text)
				})
			case err := <-done:
				a.QueueUpdateDraw(func() {
					if err != nil {
						modal := tview.NewModal()
						modal.SetBackgroundColor(tcell.ColorDarkRed)
						modal.SetText(fmt.Sprintf("Discovery failed: %v", err))
						modal.AddButtons([]string{"Quit"})
						modal.SetDoneFunc(func(buttonIndex int, buttonLabel string) {
							if buttonLabel == "Quit" {
								a.Stop()
							}
						})
						a.SetRoot(modal, false)
					} else {
						a.instances = vppList(a.probectl.Instances())
						a.instanceList.SetInstances(a.instances)
						a.rootFlex = a.flexLayout()
						a.SetRoot(a.rootFlex, true)
					}
				})
				return
			}
		}
	}()
}

func (a *App) showInstance(instance *VPP) {
	a.infoPanel.SetInstance(instance)
	a.interfaceTable.SetInterfaces(instance.Interfaces)
	a.pagesPanel.SetInstance(instance)
}

func (a *App) refreshInstance(index int) {
	instance := a.instances[index]
	a.instanceList.UpdateInstance(index, instance)
	if a.instanceList.GetCurrentItemIndex() == index {
		a.showInstance(instance)
	}
}

func (a *App) afterFocus(p tview.Primitive) {
	switch p.(type) {
	case *InstanceList:
		a.statusBar.SetKeyBinds([]KeyBind{
			{Key: "Enter", Action: "select instance"},
			{Key: "Ctrl-R", Action: "discover instances"},
			{Key: "/", Action: "search"},
			{Key: "Tab", Action: "switch panel"},
			{Key: "q", Action: "quit"},
		})
	case *InterfaceTable:
		a.statusBar.SetKeyBinds([]KeyBind{
			{Key: "Enter", Action: "select interface"},
			{Key: "Ctrl-R", Action: "reload interfaces"},
			{Key: "Tab", Action: "switch panel"},
			{Key: "q", Action: "quit"},
		})
	default:
		a.statusBar.SetKeyBinds([]KeyBind{
			{Key: "Tab/Shift-Tab", Action: "switch next/previous panel"},
			{Key: "F2", Action: "toggle log panel"},
			{Key: "q", Action: "quit"},
		})
	}
}

func (a *App) onInput(e *tcell.EventKey) *tcell.EventKey {
	switch e.Key() {
	/*case tcell.KeyF2:
	if a.logPanel.GetVisible() {
		a.logPanel.SetVisible(false)
		if a.rootFlex != nil {
			a.rootFlex.ResizeItem(a.logPanel, 1, 0)
		}
	} else {
		a.logPanel.SetVisible(true)
		if a.rootFlex != nil {
			a.rootFlex.ResizeItem(a.logPanel, 0, 1)
		}
	}*/
	case tcell.KeyCtrlQ:
		a.Suspend(func() {
			debug.PrintStack()
		})
	case tcell.KeyCtrlC:
		a.Suspend(func() {
			fmt.Fprintln(os.Stderr, stack.Trace().String())
		})
		a.Stop()
	case tcell.KeyRune:
		switch e.Rune() {
		case 'q':
			a.Stop()
		}
	case tcell.KeyTab:
		a.focusMgr.FocusNext()
		return nil
	case tcell.KeyBacktab:
		a.focusMgr.FocusPrevious()
		return nil
	case tcell.KeyCtrlR:
		if len(a.instances) != 0 {
			a.RunDiscovery()
			return nil
		}
	case tcell.KeyRight:
		if a.pagesPanel.HasFocus() {
			a.pagesPanel.nextPage()
			return nil
		}
	case tcell.KeyLeft:
		if a.pagesPanel.HasFocus() {
			a.pagesPanel.prevPage()
			return nil
		}
	}
	return e
}

func (a *App) periodicRefresh(period time.Duration) {
	logrus.Debugf("starting periodic refresh every %v", period)
	defer a.wg.Done()

	t := time.NewTicker(period)
	for {
		select {
		case <-a.ctx.Done():
			logrus.Debugf("stopping periodic refresh")
			return
		case <-t.C:
			if len(a.instances) == 0 {
				continue
			}
			a.QueueUpdateDraw(func() {
				if a.instanceList.GetCurrentItem() != nil {
					a.refreshInstance(a.instanceList.GetCurrentItemIndex())
				}
			})
		}
	}
}
