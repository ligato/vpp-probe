package docker

import (
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

func init() {
	providers.RegisterConnector(providers.Docker, func(opts ...interface{}) (probe.Provider, error) {
		return DefaultProvider()
	})
}
