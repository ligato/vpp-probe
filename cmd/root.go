package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/cn-infra/v2/logging"
	logrus2 "go.ligato.io/cn-infra/v2/logging/logrus"

	"go.ligato.io/vpp-probe/internal/version"
)

const logo = `
 ___    _________________                        ______         
 __ |  / /__  __ \__  __ \   _______________________  /______  
 __ | / /__  /_/ /_  /_/ /_____  __ \_  ___/  __ \_  __ \  _ \  %s
 __ |/ / _  ____/_  ____/_____  /_/ /  /   / /_/ /  /_/ /  __/  %s
 _____/  /_/     /_/        _  .___//_/    \____//_.___/\___/   %s
                            /_/
`

// Execute executes a root command using default behavior
func Execute() {
	cli := NewProbeCli()
	cmd := NewRootCmd(cli)

	if err := cmd.Execute(); err != nil {
		logrus.Fatalf("ERROR: %v", err)
	}
}

// NewRootCmd returns new root command
func NewRootCmd(cli *ProbeCli) *cobra.Command {
	var (
		glob GlobalFlags
		opts ProviderFlags
	)
	cmd := &cobra.Command{
		Use:           "vpp-probe [flags] [command]",
		Short:         "vpp-probe is a tool for inspecting VPP instances",
		Long:          fmt.Sprintf(logo, version.Short(), version.BuildTime(), version.BuiltBy()),
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			initOptions(glob)

			return cli.Initialize(opts)
		},
	}

	cmd.Flags().SortFlags = false
	cmd.PersistentFlags().SortFlags = false

	flags := cmd.PersistentFlags()
	opts.AddFlags(flags)
	glob.AddFlags(flags)

	cmd.InitDefaultVersionFlag()
	cmd.InitDefaultHelpFlag()
	cmd.Flags().Lookup("help").Hidden = true

	cmd.AddCommand(
		newVersionCmd(),
		NewInspectorCmd(cli),
		NewDiscoverCmd(cli),
		NewTracerCmd(cli),
	)

	cmd.InitDefaultHelpCmd()
	for _, c := range cmd.Commands() {
		if c.Name() == "help" {
			c.Hidden = true
		}
	}

	return cmd
}

func initOptions(opts GlobalFlags) {
	if os.Getenv("VPP_PROBE_DEBUG") != "" {
		opts.Debug = true
	}
	if opts.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if opts.LogLevel != "" {
		if lvl, err := logrus.ParseLevel(opts.LogLevel); err == nil {
			logrus.SetLevel(lvl)
			if lvl == logrus.TraceLevel {
				logrus.SetReportCaller(true)
				logrus2.DefaultLogger().SetLevel(logging.LogLevel(lvl))
			}
		} else {
			logrus.Warnf("log level invalid: %v", err)
		}
	} else if !opts.Debug {
		logrus.SetLevel(logrus.InfoLevel)
		logrus2.DefaultLogger().SetLevel(logging.ErrorLevel)
	}
}
