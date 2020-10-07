package localprobe

import (
	"go.ligato.io/vpp-probe/probe"
)

// Provider discovers instances running on the host locally.
type Provider struct{}

// NewProvider returns new
func NewProvider() (*Provider, error) {
	provider := &Provider{}
	return provider, nil
}

func (l *Provider) Discover(query ...interface{}) ([]probe.Handler, error) {
	instance := &Handler{}
	return []probe.Handler{instance}, nil
}
