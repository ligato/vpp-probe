// Package cmd contains implementation of the CLI commands.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.ligato.io/cn-infra/v2/logging"
	infralogrus "go.ligato.io/cn-infra/v2/logging/logrus"

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
	cli, err := NewProbeCli()
	if err != nil {
		logrus.Fatalf("%v", err)
	}

	root := NewRootCmd(cli)

	if err := root.Execute(); err != nil {
		logrus.Fatalf("%v", err)
	}
}

// NewRootCmd returns new root command
func NewRootCmd(cli Cli) *cobra.Command {
	var (
		glob GlobalOptions
		opts ProbeOptions
	)
	cmd := &cobra.Command{
		Use:           "vpp-probe [options] [command]",
		Short:         "vpp-probe is a tool for inspecting VPP instances",
		Long:          fmt.Sprintf(logo, version.Short(), version.BuildTime(), version.BuiltBy()),
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			InitOptions(cli, glob)

			return cli.Initialize(opts)
		},
		TraverseChildren: true,
	}

	cmd.SetIn(cli.In())
	cmd.SetOut(cli.Out())
	cmd.SetErr(cli.Err())

	cmd.Flags().SortFlags = false
	cmd.PersistentFlags().SortFlags = false

	opts.InstallFlags(cmd.PersistentFlags())
	glob.InstallFlags(cmd.PersistentFlags())

	cmd.InitDefaultVersionFlag()
	cmd.InitDefaultHelpFlag()
	cmd.Flags().Lookup("help").Hidden = true

	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(
		NewInspectorCmd(cli),
		NewTopologyCmd(cli),
		NewDiscoverCmd(cli),
		NewTraceCmd(cli),
		NewExecCmd(cli),
	)

	cmd.InitDefaultHelpCmd()
	for _, c := range cmd.Commands() {
		if c.Name() == "help" {
			c.Hidden = true
		}
	}

	return cmd
}

func InitOptions(cli Cli, opts GlobalOptions) {
	// color mode
	if opts.Color == "" && os.Getenv("NO_COLOR") != "" {
		// https://no-color.org/
		opts.Color = "never"
	}
	switch strings.ToLower(opts.Color) {
	case "auto", "":
		if !cli.Out().IsTerminal() {
			color.Disable()
		}
	case "on", "enabled", "always", "1", "true":
		color.Enable = true
	case "off", "disabled", "never", "0", "false":
		color.Disable()
	default:
		logrus.Fatalf("invalid color mode: %q", opts.Color)
	}

	// debug mode
	if os.Getenv("VPP_PROBE_DEBUG") != "" {
		opts.Debug = true
	}
	if opts.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// log level
	if loglvl := os.Getenv("VPP_PROBE_LOGLEVEL"); loglvl != "" {
		opts.LogLevel = loglvl
	}
	if opts.LogLevel != "" {
		if lvl, err := logrus.ParseLevel(opts.LogLevel); err == nil {
			logrus.SetLevel(lvl)
			if lvl >= logrus.TraceLevel {
				logrus.SetReportCaller(true)
				infralogrus.DefaultLogger().SetLevel(logging.LogLevel(lvl))
			}
		} else {
			logrus.Fatalf("log level invalid: %v", err)
		}
	} else if !opts.Debug {
		logrus.SetLevel(logrus.InfoLevel)
		infralogrus.DefaultLogger().SetLevel(logging.ErrorLevel)
	}
}

var formatter = &logrus.TextFormatter{
	EnvironmentOverrideColors: true,
	CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
		const modulePath = "go.ligato.io/vpp-probe"
		call := strings.TrimPrefix(frame.Function, modulePath)
		function = fmt.Sprintf("%s()", strings.TrimPrefix(call, "/"))
		_, file = filepath.Split(frame.File)
		file = fmt.Sprintf("%s:%d", file, frame.Line)
		return color.Debug.Sprint(function), color.Secondary.Sprint(file)
	},
}

func init() {
	logrus.SetFormatter(formatter)
}
