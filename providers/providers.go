package providers

import (
	"fmt"

	"go.ligato.io/vpp-probe/probe"
)

// Env
type Env = probe.Env

const (
	Local  = "local"
	Kube   = "kube"
	Docker = "docker"
)

// Provider
type Provider struct {
	env       Env
	connectFn ConnectFunc
}

func (p *Provider) Connect(a ...interface{}) (probe.Provider, error) {
	return p.connectFn(a...)
}

type ConnectFunc = func(...interface{}) (probe.Provider, error)

var (
	registeredProviders = map[Env]Provider{}
)

func Register(env Env, connectFn ConnectFunc) {
	if _, ok := registeredProviders[env]; ok {
		panic(fmt.Sprintf("duplicate registration for env %q", env))
	}
	registeredProviders[env] = Provider{
		env:       env,
		connectFn: connectFn,
	}
}

func RegisterConnector(env Env, newFn ConnectFunc) {
	Register(env, newFn)
}

func Get(env Env) (*Provider, error) {
	if _, ok := registeredProviders[env]; !ok {
		return nil, fmt.Errorf("unknown env %v", env)
	}
	p := registeredProviders[env]
	return &p, nil
}

func Connect(env Env, opts ...interface{}) (probe.Provider, error) {
	if _, ok := registeredProviders[env]; !ok {
		return nil, fmt.Errorf("unknown env %v", env)
	}
	p := registeredProviders[env]
	return p.Connect(opts...)
}
