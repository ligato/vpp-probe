package termui

import (
	"github.com/gdamore/tcell"
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
	PanelTitleColor:                      tcell.ColorWhite,
	PanelBorderColor:                     tcell.ColorDimGray,
	PanelTitleSelectedColor:              tcell.ColorGoldenrod,
	PanelBorderSelectedColor:             tcell.ColorLightGoldenrodYellow,
	PanelSelectedBackgroundColor:         tcell.ColorSteelBlue,
	PanelSelectedBackgroundInactiveColor: tcell.ColorDimGray,
}
