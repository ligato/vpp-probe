package kube

import (
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
)

func init() {
	providers.Register(providers.Kube, func(opts ...interface{}) (probe.Provider, error) {
		var kubeconfig, context string
		if len(opts) > 0 {
			kubeconfig = opts[0].(string)
		}
		if len(opts) > 1 {
			context = opts[1].(string)
		}
		return NewProvider(kubeconfig, context)
	})
}
