package cmd

import (
	"fmt"
	"strings"

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

	// vpp related

	APISocket   string
	StatsSocket string

	// provider-specific

	Docker struct {
		Host string
	}
	Kube struct {
		Kubeconfig string
		Context    string
	}
}

func (f *ProviderFlags) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&f.Env, "env", "", "Environment type in which VPP is running (local, kube)")
	flags.StringArrayVarP(&f.Queries, "query", "q", nil, "Query parameters")

	// vpp flags
	flags.StringVar(&f.APISocket, "apisock", "/run/vpp/api.sock", "Path to VPP binary API socket file")
	flags.StringVar(&f.StatsSocket, "statsock", "/run/vpp/stats.sock", "Path to VPP stats API socket file")

	// docker flags
	flags.StringVarP(&f.Docker.Host, "dockerhost", "H", "", "Daemon socket(s) to connect to\n")

	// kube flags
	flags.StringVar(&f.Kube.Kubeconfig, "kubeconfig", "", "Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG)")
	flags.StringVar(&f.Kube.Context, "kubecontext", "", "The name of the kubeconfig context to use")

}

func SetupController(glob Flags) (*controller.Controller, error) {
	env := resolveEnv(glob)

	logrus.Infof("Setting up %v provider env", env)

	providers, err := SetupProvider(env, glob.ProviderFlags)
	if err != nil {
		return nil, err
	}

	logrus.Infof("adding %v providers", len(providers))

	return newController(providers...), nil
}

func newController(providers ...probe.Provider) *controller.Controller {
	probectl := controller.NewController()

	for _, provider := range providers {
		if err := probectl.AddProvider(provider); err != nil {
			logrus.Warnf("add provider failed: %v", err)
			continue
		}
		logrus.Infof("%v provider %v connected", provider.Env(), provider.Name())
	}

	return probectl
}

func SetupProvider(env probe.Env, opt ProviderFlags) ([]probe.Provider, error) {
	switch env {
	case providers.Local:
		provider, err := local.NewProvider()
		if err != nil {
			return nil, err
		}
		return []probe.Provider{provider}, nil
	case providers.Kube:
		provider, err := setupKubeProvides(opt.Kube.Kubeconfig, opt.Kube.Context)
		if err != nil {
			return nil, err
		}
		return provider, nil
	case providers.Docker:
		provider, err := docker.NewProvider(opt.Docker.Host)
		if err != nil {
			return nil, err
		}
		return []probe.Provider{provider}, nil
	default:
		return nil, fmt.Errorf("invalid env: %q", env)
	}
}

func setupKubeProvides(kubeconfig, context string) ([]probe.Provider, error) {
	var providers []probe.Provider

	contexts := strings.Split(context, ",")
	for _, ctx := range contexts {
		provider, err := kube.NewProvider(kubeconfig, ctx)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}

	return providers, nil
}

func resolveEnv(glob Flags) (env providers.Env) {
	if glob.Env != "" {
		return providers.Env(glob.Env)
	}
	defer func() {
		logrus.Debugf("env resolved to %v", env)
	}()
	if glob.Docker.Host != "" {
		return providers.Docker
	}
	if glob.Kube.Kubeconfig != "" || glob.Kube.Context != "" {
		return providers.Kube
	}
	return providers.Local
}
