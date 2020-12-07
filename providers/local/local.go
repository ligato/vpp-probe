package local

import (
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

func init() {
	providers.Register(providers.Local, func(opts ...interface{}) (probe.Provider, error) {
		return NewProvider()
	})
}
