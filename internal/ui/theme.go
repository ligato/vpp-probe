package ui

import (
	"github.com/gdamore/tcell/v2"
)

type Theme struct {
	PanelTitleColor                      tcell.Color
	PanelBorderColor                     tcell.Color
	PanelTitleSelectedColor              tcell.Color
	PanelBorderSelectedColor             tcell.Color
	PanelSelectedBackgroundColor         tcell.Color
	PanelSelectedBackgroundInactiveColor tcell.Color
}

// Styles defines theme defaults.
var Styles = Theme{
	PanelTitleColor:                      tcell.ColorLightGray,
	PanelBorderColor:                     tcell.ColorDimGray,
	PanelTitleSelectedColor:              tcell.ColorGoldenrod,
	PanelBorderSelectedColor:             tcell.ColorLightGoldenrodYellow,
	PanelSelectedBackgroundColor:         tcell.ColorMidnightBlue,
	PanelSelectedBackgroundInactiveColor: tcell.Color236,
}
