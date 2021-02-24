package cmd

import (
	"github.com/spf13/pflag"
)

type GlobalOptions struct {
	Debug    bool
	LogLevel string
	Color    string
	// TODO: support config file
	// Config string
}

func (glob *GlobalOptions) InstallFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&glob.Debug, "debug", "D", false, "Enable debug mode")
	flags.StringVarP(&glob.LogLevel, "loglevel", "L", "", "Set logging level")
	flags.StringVar(&glob.Color, "color", "", "Color mode; auto / always / off")
}

type ProbeOptions struct {
	Env     string
	Queries []string

	Local struct {
		CLISocket   string
		APISocket   string
		StatsSocket string
	}
	Docker struct {
		Host string
	}
	Kube struct {
		Kubeconfig string
		Context    string
	}
}

func (f *ProbeOptions) InstallFlags(flags *pflag.FlagSet) {
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

	// kube flags
	flags.StringVar(&f.Kube.Kubeconfig, "kubeconfig", "", "Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG) (implies kube env)")
	flags.StringVar(&f.Kube.Context, "kubecontext", "", "The name of the kubeconfig context to use, multiple contexts separated by a comma `,` (implies kube env)\n")

	// docker flags
	flags.StringVar(&f.Docker.Host, "dockerhost", "", "Daemon socket(s) to connect to (implies docker env)\n")

	// local flags
	flags.StringVar(&f.Local.CLISocket, "clisock", "", "Path to VPP CLIsocket file (used in local env)")
	flags.StringVar(&f.Local.APISocket, "apisock", "", "Path to VPP binary API socket file (used in local env)")
	flags.StringVar(&f.Local.StatsSocket, "statsock", "", "Path to VPP stats API socket file (used in local env)\n")
}
