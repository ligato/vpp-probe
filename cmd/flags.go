package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"go.ligato.io/vpp-probe/controller"
	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/providers/docker"
	"go.ligato.io/vpp-probe/providers/kube"
	"go.ligato.io/vpp-probe/providers/local"
)

type Flags struct {
	GlobalFlags
	ProviderFlags
}

func (glob *Flags) AddFlags(flags *pflag.FlagSet) {
	glob.GlobalFlags.AddFlags(flags)
	glob.ProviderFlags.AddFlags(flags)
}

type GlobalFlags struct {
	Debug    bool
	LogLevel string
	// TODO: support config file
	// Config string
}

func (glob *GlobalFlags) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&glob.Debug, "debug", "D", false, "Enable debug mode")
	flags.StringVar(&glob.LogLevel, "loglevel", "", "Set logging level")
}

type ProviderFlags struct {
	Env     string
	Queries []string

	LocalFlags
	DockerFlags
	KubeFlags
}

func (glob *ProviderFlags) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&glob.Env, "env", "", "Environment type in which VPP is running (local, kube)")
	flags.StringArrayVarP(&glob.Queries, "query", "q", nil, "Query parameters")

	glob.LocalFlags.AddFlags(flags)
	glob.KubeFlags.AddFlags(flags)
	glob.DockerFlags.AddFlags(flags)
}

type LocalFlags struct {
	APISocket   string
	StatsSocket string
}

func (local *LocalFlags) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&local.APISocket, "apisock", "/run/vpp/api.sock", "Path to VPP binary API socket file")
	flags.StringVar(&local.StatsSocket, "statsock", "/run/vpp/stats.sock", "Path to VPP stats API socket file")
}

type DockerFlags struct {
	Host string
}

func (docker *DockerFlags) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&docker.Host, "dockerhost", "H", "", "Daemon socket(s) to connect to\n")
}

type KubeFlags struct {
	Kubeconfig string
	Context    string
}

func (kube *KubeFlags) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&kube.Kubeconfig, "kubeconfig", "", "Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG)")
	flags.StringVar(&kube.Context, "context", "", "The name of the kubeconfig context to use")
}

func SetupController(glob Flags) (*controller.Controller, error) {
	env := resolveEnv(glob)

	logrus.Infof("Setting up provider: %v", env)

	provider, err := SetupProvider(env, glob)
	if err != nil {
		return nil, err
	}

	logrus.Infof("%v provider %v connected", provider.Env(), provider.Name())

	return newController(provider), nil
}

func SetupProvider(env probe.Env, glob Flags) (probe.Provider, error) {
	switch env {
	case providers.Local:
		return local.NewProvider()
	case providers.Kube:
		provider, err := kube.NewProvider(glob.Kubeconfig, glob.Context)
		if err != nil {
			return nil, err
		}
		return provider, nil
	case providers.Docker:
		provider, err := docker.DefaultProvider()
		if err != nil {
			return nil, err
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unknown value: %q", env)
	}
}

func newController(providers ...probe.Provider) *controller.Controller {
	probectl := controller.NewController()
	for _, provider := range providers {
		if err := probectl.AddProvider(provider); err != nil {
			logrus.Warnf("add provider failed: %v", err)
		}
	}
	return probectl
}

func resolveEnv(glob Flags) (env providers.Env) {
	if glob.Env != "" {
		return providers.Env(glob.Env)
	}
	defer func() {
		logrus.Infof("env resolved to %v", env)
	}()

	if glob.Kubeconfig != "" || glob.Context != "" {
		return providers.Kube
	}
	return providers.Local
}
