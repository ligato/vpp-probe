package termui

import (
	"github.com/gdamore/tcell"
)

type Theme struct {
	PanelTitleSelectedColor  tcell.Color
	PanelBorderSelectedColor tcell.Color
}

// DefaultTheme defines theme defaults.
var DefaultTheme = Theme{
	PanelTitleSelectedColor:  tcell.ColorGoldenrod,
	PanelBorderSelectedColor: tcell.ColorLightGoldenrodYellow,
}
