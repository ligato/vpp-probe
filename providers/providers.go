package providers

import (
	"fmt"

	"go.ligato.io/vpp-probe/probe"
)

type Env = probe.Env

const (
	Local  = "local"
	Kube   = "kube"
	Docker = "docker"
)

type ConnectFunc = func(...interface{}) (probe.Provider, error)

func Register(env Env, connectFn ConnectFunc) {
	if err := register(env, provider{
		env:       env,
		connectFn: connectFn,
	}); err != nil {
		panic(err)
	}
}

func Connect(env Env, opts ...interface{}) (probe.Provider, error) {
	p, err := get(env)
	if err != nil {
		return nil, err
	}
	return p.Connect(opts...)
}

type provider struct {
	env       Env
	connectFn ConnectFunc
}

func (p *provider) Connect(a ...interface{}) (probe.Provider, error) {
	return p.connectFn(a...)
}

var (
	registeredProviders = map[Env]provider{}
)

func register(env Env, prov provider) error {
	if _, ok := registeredProviders[env]; ok {
		return fmt.Errorf("duplicate registration for env %q", env)
	}
	registeredProviders[env] = prov
	return nil
}

func get(env Env) (*provider, error) {
	p, ok := registeredProviders[env]
	if !ok {
		return nil, fmt.Errorf("unknown env %v", env)
	}
	return &p, nil
}
