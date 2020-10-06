package termui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell"
	"github.com/rivo/tview"

	"go.ligato.io/vpp-probe/client"
)

type InstanceList struct {
	*tview.List
}

func NewInstanceList() *InstanceList {
	v := &InstanceList{}
	v.List = tview.NewList()
	v.List.SetTitle("[ Instances ]")
	v.List.SetBorder(true)
	v.List.SetBorderPadding(0, 0, 1, 1)
	v.List.SetShortcutColor(tcell.ColorDodgerBlue)
	v.List.SetSecondaryTextColor(tcell.ColorGray)
	v.List.ShowSecondaryText(false)
	v.List.SetSelectedBackgroundColor(tcell.ColorDimGray)
	v.List.SetSelectedTextColor(tcell.ColorWhite)
	return v
}

func (l *InstanceList) Focus(delegate func(p tview.Primitive)) {
	l.List.SetSelectedBackgroundColor(tcell.ColorSteelBlue)
	l.List.SetTitleColor(tcell.ColorGold)
	l.List.SetBorderColor(tcell.ColorGold)
	l.List.Focus(delegate)
}

func (l *InstanceList) Blur() {
	l.List.SetSelectedBackgroundColor(tcell.ColorDimGray)
	l.List.SetTitleColor(tcell.ColorWhite)
	l.List.SetBorderColor(tcell.ColorWhite)
	l.List.Blur()
}

func (l *InstanceList) SetInstances(instances []*Instance) {
	l.List.Clear()
	for idx, instance := range instances {
		ndx := idx + 1
		var key rune
		if ndx < 10 {
			key = '0' + rune(ndx)
		}
		l.List.AddItem(instance.ID, instance.Version, key, nil)
	}
}

type InfoPanel struct {
	*tview.TextView
}

func NewInfoPanel() *InfoPanel {
	v := &InfoPanel{}
	v.TextView = tview.NewTextView()
	v.TextView.SetTitle("[ Info ]")
	v.TextView.SetBorder(true)
	v.TextView.SetBorderPadding(0, 0, 1, 1)
	v.TextView.SetDynamicColors(true)
	return v
}

func (l *InfoPanel) Focus(delegate func(p tview.Primitive)) {
	l.TextView.SetTitleColor(tcell.ColorGold)
	l.TextView.SetBorderColor(tcell.ColorGold)
	l.TextView.Focus(delegate)
}

func (l *InfoPanel) Blur() {
	l.TextView.SetTitleColor(tcell.ColorWhite)
	l.TextView.SetBorderColor(tcell.ColorWhite)
	l.TextView.Blur()
}

func (v *InfoPanel) SetInstance(instance *Instance) {
	v.Clear()
	info := []string{
		fmt.Sprintf("Handler: [steelblue]%v[-]", instance.ID),
		"---",
		fmt.Sprintf("Version: [yellow]%v[-]", instance.Version),
		fmt.Sprintf("PID: [yellow]%v[-]", instance.Pid),
		fmt.Sprintf("Clock: [yellow]%v[-]", instance.Clock),
	}
	v.TextView.SetText(strings.Join(info, "\n"))
}

type InterfaceTable struct {
	*tview.Table
}

func NewInterfaceTable() *InterfaceTable {
	v := &InterfaceTable{}
	v.Table = tview.NewTable()
	v.Table.SetTitle("[ Interfaces ]")
	v.Table.SetBorder(true)
	v.Table.SetBorderPadding(0, 0, 1, 1)
	v.Table.SetSelectable(true, false)
	v.Table.SetSelectedStyle(tcell.ColorDefault, tcell.ColorDimGray, 0)
	v.Table.SetFixed(1, 0)
	return v
}

func (l *InterfaceTable) Focus(delegate func(p tview.Primitive)) {
	l.Table.SetSelectedStyle(tcell.ColorDefault, tcell.ColorSteelBlue, 0)
	l.Table.SetTitleColor(tcell.ColorGold)
	l.Table.SetBorderColor(tcell.ColorGold)
	l.Table.Focus(delegate)
}

func (l *InterfaceTable) Blur() {
	l.Table.SetSelectedStyle(tcell.ColorDefault, tcell.ColorDimGray, 0)
	l.Table.SetTitleColor(tcell.ColorWhite)
	l.Table.SetBorderColor(tcell.ColorWhite)
	l.Table.Blur()
}

func (t *InterfaceTable) SetInterfaces(interfaces []*client.Interface) {
	t.Clear()
	header := []string{
		"Interface", "Idx", "Type", "State", "IP", "VRF", "MTUs",
	}
	for i := range header {
		tableCell := tview.NewTableCell(header[i]).
			SetAttributes(tcell.AttrUnderline).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		t.Table.SetCell(0, i, tableCell)
	}

	for idx, iface := range interfaces {
		name := iface.Name
		if len(strings.TrimSpace(iface.Tag)) > 0 {
			name = fmt.Sprintf("%s (%s)", iface.Name, iface.Tag)
		}
		ips := strings.Join(iface.IPs, ", ")
		var state string
		if iface.State == "up" {
			state = fmt.Sprintf("[green]UP[-]")
		} else {
			state = fmt.Sprintf("[red]DOWN[-]")
		}
		cols := []string{
			fmt.Sprintf("[white]%s[-]", name),
			fmt.Sprint(iface.Index),
			strings.ToUpper(iface.DevType),
			state,
			fmt.Sprintf("%s", ips),
			fmt.Sprint(iface.VRF),
			formatInterfaceMTU(iface.MTUs),
		}
		row := idx + 1
		for column, col := range cols {
			color := tcell.ColorWhite
			align := tview.AlignLeft
			maxWidth := 0
			expansion := 1
			if column == 1 || column == 3 || column == 5 {
				maxWidth = 6
				//expansion = 0
			}
			tableCell := tview.NewTableCell(col).
				SetTextColor(color).
				SetAlign(align).
				SetSelectable(true).
				SetMaxWidth(maxWidth).
				SetExpansion(expansion)
			t.Table.SetCell(row, column, tableCell)
		}
	}
}

type LogPanel struct {
	*tview.TextView
}

func NewLogPanel() *LogPanel {
	v := &LogPanel{}
	v.TextView = tview.NewTextView()
	v.TextView.SetTitle("[ Log ]")
	v.TextView.SetBorder(true)
	v.TextView.SetBorderPadding(0, 0, 1, 1)
	v.TextView.SetTextColor(tcell.ColorDimGray)
	v.TextView.SetDynamicColors(true)
	return v
}

func (l *LogPanel) Focus(delegate func(p tview.Primitive)) {
	l.TextView.SetTitleColor(tcell.ColorGold)
	l.TextView.SetBorderColor(tcell.ColorGold)
	l.TextView.Focus(delegate)
}

func (l *LogPanel) Blur() {
	l.TextView.SetTitleColor(tcell.ColorWhite)
	l.TextView.SetBorderColor(tcell.ColorWhite)
	l.TextView.Blur()
}

func (l *LogPanel) SetLogs(lines []string) {
	l.TextView.SetText(strings.Join(lines, "\n"))
}

type StatusBar struct {
	*tview.TextView
}

func NewStatusBar() *StatusBar {
	v := &StatusBar{}
	v.TextView = tview.NewTextView()
	v.TextView.SetBorderPadding(0, 0, 1, 1)
	v.TextView.SetBackgroundColor(tcell.ColorDimGray)
	v.TextView.SetTextColor(tcell.ColorWhite)
	v.TextView.SetDynamicColors(true)
	return v
}

func (v *StatusBar) SetKeyBinds(binds []KeyBind) {
	var keyBinds []string
	for _, bind := range binds {
		s := fmt.Sprintf("[yellow:black] %s [black:white] %s [white:darkgray]", bind.Key, bind.Action)
		keyBinds = append(keyBinds, s)
	}
	v.TextView.SetText(" " + strings.Join(keyBinds, " "))
}
