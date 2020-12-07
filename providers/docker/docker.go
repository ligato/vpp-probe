package docker

import (
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

func init() {
	providers.Register(providers.Docker, func(opts ...interface{}) (probe.Provider, error) {
		var endpoint string
		if len(opts) > 0 {
			endpoint = opts[0].(string)
		}
		return NewProvider(endpoint)
	})
}
