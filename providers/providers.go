// Package providers defines a common API for providers.
package providers

import (
	"go.ligato.io/vpp-probe/probe"
)

type Env string

const (
	Local  = "local"
	Kube   = "kube"
	Docker = "docker"
)

// Provider provides ways to discover instances.
type Provider interface {
	// Env returns the environment type of the provider.
	Env() string

	// Name returns a name of the provider.
	Name() string

	// Query runs query with list of parameters used as filters and returns a list
	// of Handler for
	Query(params ...map[string]string) ([]probe.Handler, error)
}
