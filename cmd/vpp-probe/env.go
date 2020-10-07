package main

import (
	"fmt"

	"go.ligato.io/vpp-probe/controller"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/probe/kubeprobe"
)

// Env defines runtime environment type for VPP instances.
type Env string

const (
	HostEnv   = "host"
	KubeEnv   = "kube"
	DockerEnv = "docker"
)

func resolveEnv(glob GlobalFlags) Env {
	if glob.Env != "" {
		return Env(glob.Env)
	}
	if glob.Kubeconfig != "" || len(glob.Selectors) > 0 {
		return KubeEnv
	}
	return HostEnv
}

func setupProvider(glob GlobalFlags) (probe.Provider, error) {
	env := resolveEnv(glob)
	switch env {
	case HostEnv:
		return controller.DefaultProvider, nil
	case KubeEnv:
		provider, err := kubeprobe.NewProvider(glob.Kubeconfig, glob.Selectors)
		if err != nil {
			return nil, err
		}
		return provider, nil
	case DockerEnv:
		return nil, fmt.Errorf("docker not supported yet")
	default:
		return nil, fmt.Errorf("unknown value: %q", env)
	}
}
