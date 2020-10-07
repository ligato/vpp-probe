package termui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell"
	"github.com/rivo/tview"

	"go.ligato.io/vpp-probe/vpp/types"
)

func NewPanelBox(title string) *tview.Box {
	panel := tview.NewBox()
	panel.SetTitle(fmt.Sprintf(" [ %s ] ", title))
	panel.SetBorder(true)
	panel.SetBorderPadding(0, 0, 1, 1)
	panel.SetBorderColor(Styles.PanelBorderColor)
	panel.SetBorderColor(Styles.PanelTitleColor)
	return panel
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

func (l *InstanceList) Focus(delegate func(p tview.Primitive)) {
	l.List.SetSelectedBackgroundColor(Styles.PanelSelectedBackgroundColor)
	l.List.SetTitleColor(Styles.PanelTitleSelectedColor)
	l.List.SetBorderColor(Styles.PanelBorderSelectedColor)
	l.List.Focus(delegate)
}

func (l *InstanceList) Blur() {
	l.List.SetSelectedBackgroundColor(Styles.PanelSelectedBackgroundInactiveColor)
	l.List.SetTitleColor(Styles.PanelTitleColor)
	l.List.SetBorderColor(Styles.PanelBorderColor)
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
	v.TextView.Box = NewPanelBox("Info")
	v.TextView.SetDynamicColors(true)
	return v
}

func (v *InfoPanel) Focus(delegate func(p tview.Primitive)) {
	v.TextView.SetTitleColor(Styles.PanelTitleSelectedColor)
	v.TextView.SetBorderColor(Styles.PanelBorderSelectedColor)
	v.TextView.Focus(delegate)
}

func (v *InfoPanel) Blur() {
	v.TextView.SetTitleColor(Styles.PanelTitleColor)
	v.TextView.SetBorderColor(Styles.PanelBorderColor)
	v.TextView.Blur()
}

func (v *InfoPanel) SetInstance(instance *Instance) {
	v.Clear()
	info := []string{
		fmt.Sprintf("Instance: [steelblue]%v[-]", instance.ID),
	}
	if instance.Error != nil {
		info = append(info,
			fmt.Sprintf("Error: [red]%v[-]", instance.Error.Error()),
		)
	}
	info = append(info, []string{
		fmt.Sprintf("Version: [yellow]%v[-]", instance.Version),
		fmt.Sprintf("PID: [yellow]%v[-]", instance.Pid),
		fmt.Sprintf("Clock: [yellow]%v[-]", instance.Clock),
	}...)
	v.TextView.SetText(strings.Join(info, "\n"))
}

type InterfaceTable struct {
	*tview.Table
}

func NewInterfaceTable() *InterfaceTable {
	v := &InterfaceTable{}
	v.Table = tview.NewTable()
	v.Table.Box = NewPanelBox("Interfaces")
	v.Table.SetSelectable(true, false)
	v.Table.SetSelectedStyle(tcell.ColorDefault, tcell.ColorDimGray, 0)
	v.Table.SetFixed(1, 0)
	return v
}

func (l *InterfaceTable) Focus(delegate func(p tview.Primitive)) {
	l.Table.SetSelectedStyle(tcell.ColorDefault, Styles.PanelSelectedBackgroundColor, 0)
	l.Table.SetTitleColor(Styles.PanelTitleSelectedColor)
	l.Table.SetBorderColor(Styles.PanelBorderSelectedColor)
	l.Table.Focus(delegate)
}

func (l *InterfaceTable) Blur() {
	l.Table.SetSelectedStyle(tcell.ColorDefault, Styles.PanelSelectedBackgroundInactiveColor, 0)
	l.Table.SetTitleColor(Styles.PanelTitleColor)
	l.Table.SetBorderColor(Styles.PanelBorderColor)
	l.Table.Blur()
}

func (t *InterfaceTable) SetInterfaces(interfaces []*types.Interface) {
	t.Clear()
	header := []string{
		"Interface", "Idx", "Type", "Status", "IP", "VRF", "MTUs",
	}
	for i := range header {
		tableCell := tview.NewTableCell(header[i]).
			SetAttributes(tcell.AttrUnderline).
			SetTextColor(tcell.ColorBlack).
			SetBackgroundColor(tcell.ColorWhite).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		t.Table.SetCell(0, i, tableCell)
	}
	for idx, iface := range interfaces {
		cols := []string{
			formatInterfaceName(iface),
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
	v.TextView.Box = NewPanelBox("Log")
	v.TextView.SetTextColor(tcell.ColorDimGray)
	v.TextView.SetDynamicColors(true)
	return v
}

func (l *LogPanel) Focus(delegate func(p tview.Primitive)) {
	l.TextView.SetTitleColor(Styles.PanelTitleSelectedColor)
	l.TextView.SetBorderColor(Styles.PanelBorderSelectedColor)
	l.TextView.Focus(delegate)
}

func (l *LogPanel) Blur() {
	l.TextView.SetTitleColor(Styles.PanelTitleColor)
	l.TextView.SetBorderColor(Styles.PanelBorderColor)
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

type KeyBind struct {
	Key    string
	Action string
}

func (v *StatusBar) SetKeyBinds(binds []KeyBind) {
	var keyBinds []string
	for _, bind := range binds {
		s := fmt.Sprintf("[yellow:black] %s [black:white] %s [white:darkgray]", bind.Key, bind.Action)
		keyBinds = append(keyBinds, s)
	}
	v.TextView.SetText(" " + strings.Join(keyBinds, " "))
}
