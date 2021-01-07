package cmd

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/probe/controller"
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
	flags.StringVarP(&glob.LogLevel, "loglevel", "L", "", "Set logging level")
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
	flags.StringVarP(&f.Env, "env", "e", "",
		`Environment type in which VPP is running. Supported environments are local, docker and kube,
where VPP is running as a local process, as a Docker container or as a Kubernetes pod, respectivelly.
`)
	flags.StringArrayVarP(&f.Queries, "query", "q", nil,
		`Selector query to filter VPP instances on, supports '=' (e.g --query key1=value1). 
Multiple parameters in a single query (using AND logic) are separated by a comma (e.g. -q key1=val1,key2=val2) and 
multiple queries (using OR logic) can be defined as additional flag options (e.g. -q k1=v1 -q k1=v2). 
Parameter types depend on probe environment (defined with --env).
`)

	// vpp flags
	flags.StringVar(&f.APISocket, "apisock", "/run/vpp/api.sock", "Path to VPP binary API socket file")
	flags.StringVar(&f.StatsSocket, "statsock", "/run/vpp/stats.sock", "Path to VPP stats API socket file")

	// docker flags
	flags.StringVar(&f.Docker.Host, "dockerhost", "", "Daemon socket(s) to connect to\n")

	// kube flags
	flags.StringVar(&f.Kube.Kubeconfig, "kubeconfig", "", "Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG)")
	flags.StringVar(&f.Kube.Context, "kubecontext", "", "The name of the kubeconfig context to use")

}

func SetupController(glob Flags) (*controller.Controller, error) {
	env := resolveEnv(glob)

	logrus.Debugf("Setting up %v provider env", env)

	pvds, err := SetupProvider(env, glob.ProviderFlags)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("adding %v providers", len(pvds))

	return newController(pvds...), nil
}

func newController(providers ...probe.Provider) *controller.Controller {
	probectl := controller.NewController()

	for _, provider := range providers {
		if err := probectl.AddProvider(provider); err != nil {
			logrus.Warnf("add provider failed: %v", err)
			continue
		}
		logrus.Debugf("%v provider %v connected", provider.Env(), provider.Name())
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
		provider, err := setupKubeProviders(opt.Kube.Kubeconfig, opt.Kube.Context)
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

func setupKubeProviders(kubeconfig, context string) ([]probe.Provider, error) {
	var pvds []probe.Provider

	contexts := strings.Split(context, ",")
	for _, ctx := range contexts {
		provider, err := kube.NewProvider(kubeconfig, ctx)
		if err != nil {
			return nil, err
		}
		pvds = append(pvds, provider)
	}

	return pvds, nil
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
