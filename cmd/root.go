package cmd

import (
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
 __ | / /__  /_/ /_  /_/ /_____  __ \_  ___/  __ \_  __ \  _ \ 
 __ |/ / _  ____/_  ____/_____  /_/ /  /   / /_/ /  /_/ /  __/ 
 _____/  /_/     /_/        _  .___//_/    \____//_.___/\___/  
                            /_/
`

// Execute creates root command and executes it
func Execute() {
	rootCmd := NewRootCmd()

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatalf("execute error: %v", err)
	}
}

// NewRootCmd returns new root command
func NewRootCmd() *cobra.Command {
	var (
		glob Flags
	)
	cmd := &cobra.Command{
		Use:           "vpp-probe [flags] [command]",
		Short:         "vpp-probe is a tool for inspecting VPP instances",
		Long:          logo,
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			Init(glob)
		},
	}
	flags := cmd.PersistentFlags()
	glob.AddFlags(flags)

	cmd.AddCommand(
		versionCmd(),
		inspectorCmd(&glob),
		NewDiscoverCmd(&glob),
		NewTracerCmd(&glob),
	)
	return cmd
}

func Init(glob Flags) {
	if os.Getenv("VPP_PROBE_DEBUG") != "" {
		glob.Debug = true
	}
	if glob.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if glob.LogLevel != "" {
		if lvl, err := logrus.ParseLevel(glob.LogLevel); err == nil {
			logrus.SetLevel(lvl)
			if lvl == logrus.TraceLevel {
				logrus2.DefaultLogger().SetLevel(logging.LogLevel(lvl))
			}
		} else {
			logrus.Warnf("log level error: %v", err)
		}
	} else {
		logrus.SetLevel(logrus.InfoLevel)
		logrus2.DefaultLogger().SetLevel(logging.ErrorLevel)
	}
}
