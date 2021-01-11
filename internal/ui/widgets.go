package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/sirupsen/logrus"
	tview "gitlab.com/tslocum/cview"

	"go.ligato.io/vpp-probe/internal/version"
	"go.ligato.io/vpp-probe/vpp/api"
)

type Navbar struct {
	*tview.TextView
}

func NewNavbar() *Navbar {
	n := &Navbar{
		TextView: tview.NewTextView(),
	}
	n.TextView.SetPadding(0, 0, 1, 1)
	logo := fmt.Sprintf(`                                   __      
 _  _____  ___  _______  _______  / /  ___ 
| |/ / _ \/ _ \/___/ _ \/ __/ _ \/ _ \/ -_)
|___/ .__/ .__/   / .__/_/  \___/_.__/\__/  %s
   /_/  /_/      /_/                       `, version.String())
	n.SetText(logo)
	return n
}

type InstanceList struct {
	*tview.List
}

func NewInstanceList() *InstanceList {
	v := &InstanceList{}
	v.List = tview.NewList()
	v.List.Box = NewPanelBox("Instances")
	v.List.SetShortcutColor(tcell.ColorDodgerBlue)
	v.List.SetSecondaryTextColor(tcell.ColorGray)
	v.List.ShowSecondaryText(false)
	v.List.SetSelectedBackgroundColor(Styles.PanelSelectedBackgroundColor)
	v.List.SetSelectedTextColor(tcell.ColorWhite)
	return v
}

func (l *InstanceList) SetInstances(instances []*VPP) {
	l.List.Clear()
	for idx, instance := range instances {
		ndx := idx + 1
		var key rune
		if ndx < 10 {
			key = '0' + rune(ndx)
		}
		item := tview.NewListItem(instanceItemText(instance))
		item.SetShortcut(key)
		item.SetReference(instance)
		l.List.AddItem(item)
	}
}

func (l *InstanceList) UpdateInstance(index int, instance *VPP) {
	l.SetItemText(index, instanceItemText(instance), "")
}

func instanceItemText(instance *VPP) string {
	text := instance.ID
	if instance.Updating {
		text += fmt.Sprintf(" [gold::bi]updating..[-:-:-]")
	}
	return text
}

type InfoPanel struct {
	*tview.TextView
}

func NewInfoPanel() *InfoPanel {
	v := &InfoPanel{}
	v.TextView = tview.NewTextView()
	v.TextView.Box = NewPanelBox("Info")
	v.TextView.SetDynamicColors(true)
	v.TextView.SetWrap(false)
	return v
}

func (v *InfoPanel) SetInstance(vpp *VPP) {
	v.Clear()
	status := vpp.Status()
	info := []string{
		fmt.Sprintf("Instance: [steelblue]%v[-]", vpp.Handler().ID()),
		"",
		fmt.Sprintf("Status:   [%s]CLI %v[-] / [%s]API %v[-] / [%s]Stats %v[-]",
			statusColor(status.CLI), status.CLI,
			statusColor(status.BinAPI), status.BinAPI,
			statusColor(status.StatsAPI), status.StatsAPI),
	}
	if vpp.Error != nil {
		info = append(info,
			fmt.Sprintf("Error: [red]%v[-]", vpp.Error.Error()),
		)
	}
	info = append(info, "")

	var updated string
	sinceUpdate := time.Since(vpp.LastUpdate)
	if vpp.Updating {
		updated = fmt.Sprintf("updating now..")
	} else {
		updated = fmt.Sprintf("last update [%s]%v[-]", updatedColor(sinceUpdate), shortHumanDuration(sinceUpdate))
	}
	info = append(info, []string{
		fmt.Sprintf("Version: [yellow]%v[-]", vpp.Version),
		fmt.Sprintf("Uptime:  [yellow]%v[-]", vpp.Uptime),
		fmt.Sprintf("PID:     [yellow]%v[-]", vpp.Pid),
		"",
		updated,
	}...)

	v.TextView.SetText(strings.Join(info, "\n"))
}

type PagesPanel struct {
	*tview.TabbedPanels

	logsTab    *LogPanel
	statsPanel *tview.TextView
	cliOutput  *tview.TextView

	pages      []*page
	activePage int
}

type page struct {
	tview.Primitive
	Name string
}

func NewPagesPanel() *PagesPanel {
	v := &PagesPanel{}
	v.TabbedPanels = tview.NewTabbedPanels()
	v.logsTab = NewLogPanel()
	v.statsPanel = tview.NewTextView()
	v.statsPanel.Box = NewPanelBox("Stats")
	v.statsPanel.SetDynamicColors(true)
	v.cliOutput = tview.NewTextView()
	v.cliOutput.Box = NewPanelBox("CLI")
	v.cliOutput.SetDynamicColors(true)
	v.TabbedPanels.AddTab("logs", "Logs", v.logsTab)
	v.TabbedPanels.AddTab("stats", "Stats", v.statsPanel)
	v.TabbedPanels.AddTab("cli", "CLI", v.cliOutput)
	v.pages = []*page{
		{v.logsTab, "logs"},
		{v.statsPanel, "stats"},
		{v.cliOutput, "cli"},
	}
	return v
}

func (v *PagesPanel) SetInstance(instance *VPP) {
	// logs tab
	v.logsTab.SetLogs(instance.Logs)

	// stats tab
	stats := strings.Join(instance.Stats, "\n")
	v.statsPanel.SetText(tview.TranslateANSI(stats))

	// cli tab
	var clis []string
	for _, cli := range listCLIs {
		c := instance.CLIs[cli]
		clis = append(clis, fmt.Sprintf("[gray]vpp#[-] [yellow]%s[-]\n%s\n", cli, c))
	}
	text := strings.Join(clis, "\n")
	v.cliOutput.SetText(tview.TranslateANSI(text))
}

func (v *PagesPanel) nextPage() {
	nextPageIdx := v.activePage + 1
	if nextPageIdx >= len(v.pages) {
		nextPageIdx = 0
	}
	v.switchPage(nextPageIdx)
}

func (v *PagesPanel) prevPage() {
	prevPageIdx := v.activePage - 1
	if prevPageIdx < 0 {
		prevPageIdx = len(v.pages) - 1
	}
	v.switchPage(prevPageIdx)
}

func (v *PagesPanel) switchPage(idx int) {
	if idx < 0 || idx >= len(v.pages) {
		logrus.Warnf("switch page invalid index %v", idx)
		return
	}
	page := v.pages[idx]
	v.TabbedPanels.SetCurrentTab(page.Name)
	v.activePage = idx
}

type InterfaceTable struct {
	*tview.Table
}

func NewInterfaceTable() *InterfaceTable {
	v := &InterfaceTable{}
	v.Table = tview.NewTable()
	v.Table.Box = NewPanelBox("Interfaces")
	v.Table.SetSelectable(true, false)
	v.Table.SetSelectedStyle(tcell.ColorDefault, Styles.PanelSelectedBackgroundInactiveColor, 0)
	v.Table.SetFixed(1, 0)
	return v
}

func (t *InterfaceTable) SetInterfaces(interfaces []*api.Interface) {
	t.Clear()
	if len(interfaces) == 0 {
		return
	}
	header := []string{
		"Interface", "Alias", "Idx", "Type", "Status", "IP", "VRF", "MTUs",
	}
	for i := range header {
		tableCell := tview.NewTableCell(header[i])
		tableCell.SetAttributes(tcell.AttrBold)
		tableCell.SetTextColor(tcell.ColorBlack)
		tableCell.SetBackgroundColor(tcell.ColorLightGray)
		tableCell.SetAlign(tview.AlignLeft)
		tableCell.SetSelectable(false)
		t.Table.SetCell(0, i, tableCell)
	}
	for idx, iface := range interfaces {
		cols := []string{
			iface.Name,
			fmt.Sprintf("[white]%s[-]", iface.Tag),
			fmt.Sprint(iface.Index),
			strings.ToUpper(iface.DeviceType),
			formatInterfaceStatus(iface.Status),
			formatInterfaceIPs(iface.IPs),
			formatInterfaceVRF(iface.VRF),
			formatInterfaceMTU(iface.MTUs),
		}
		row := idx + 1
		for column, col := range cols {
			color := tcell.ColorWhite
			align := tview.AlignLeft
			maxWidth := 0
			expansion := 1
			if column == 2 || column == 4 || column == 6 {
				maxWidth = 6
			}
			tableCell := tview.NewTableCell(col)
			tableCell.SetTextColor(color)
			tableCell.SetAlign(align)
			tableCell.SetSelectable(true)
			tableCell.SetMaxWidth(maxWidth)
			tableCell.SetExpansion(expansion)
			t.Table.SetCell(row, column, tableCell)
		}
	}
}

type LogPanel struct {
	*tview.TextView
	logLines []string
}

func NewLogPanel() *LogPanel {
	v := &LogPanel{}
	v.TextView = tview.NewTextView()
	v.TextView.Box = NewPanelBox("Log")
	v.TextView.SetTextColor(tcell.ColorLightGray)
	v.TextView.SetBackgroundColor(tcell.ColorBlack)
	v.TextView.SetDynamicColors(true)
	v.TextView.SetMaxLines(1024)
	v.TextView.SetScrollBarVisibility(tview.ScrollBarAuto)
	v.TextView.ScrollToEnd()
	return v
}

func (l *LogPanel) SetLogs(lines []string) {
	l.logLines = lines
	l.TextView.SetText(strings.Join(lines, "\n"))
	l.TextView.ScrollToEnd()
}

/*func (t *LogPanel) InputHandler() func(key *tcell.EventKey, f func(p tview.Primitive)) {
	return t.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		inputHandler := t.TextView.InputHandler()
		if inputHandler != nil {
			inputHandler(event, setFocus)
		}
		row, _ := t.TextView.GetScrollOffset()
		_, _, _, height := t.TextView.Box.GetInnerRect()
		t.TextView.SetTitle(fmt.Sprintf(" [ Logs %d(%d)/%d ] ", row, row+height, len(t.logLines)))
	})
}*/

type StatusBar struct {
	*tview.TextView
}

func NewStatusBar() *StatusBar {
	v := &StatusBar{}
	v.TextView = tview.NewTextView()
	v.TextView.SetPadding(0, 0, 0, 0)
	v.TextView.SetBackgroundColor(tcell.ColorDefault)
	v.TextView.SetTextColor(tcell.ColorWhite)
	v.TextView.SetDynamicColors(true)
	return v
}

type KeyBind struct {
	Key    string
	Action string
}

func (v *StatusBar) SetKeyBinds(binds []KeyBind) {
	var keyBinds []string
	for _, bind := range binds {
		s := fmt.Sprintf("[yellow:darkslategray] %s [black:gray] %s [-:-]", bind.Key, bind.Action)
		keyBinds = append(keyBinds, s)
	}
	v.TextView.SetText(" " + strings.Join(keyBinds, " "))
}

func NewPanelBox(title string) *tview.Box {
	panel := tview.NewBox()
	panel.SetTitle(fmt.Sprintf(" [ %s ] ", title))
	panel.SetBorder(true)
	panel.SetPadding(0, 0, 1, 1)
	panel.SetBorderColor(Styles.PanelBorderColor)
	panel.SetTitleColor(Styles.PanelTitleColor)
	return panel
}
