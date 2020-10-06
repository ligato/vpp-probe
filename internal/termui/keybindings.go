package termui

import (
	"github.com/gdamore/tcell"
)

type KeyBind struct {
	Key    tcell.Key
	Ch     rune
	Mod    tcell.ModMask
	Action string
}
