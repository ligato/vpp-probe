package main

import (
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/controller"
	"go.ligato.io/vpp-probe/internal/termui"
	"go.ligato.io/vpp-probe/internal/version"
)

type GlobalFlags struct {
	Env   string
	Debug bool

	// Kube
	Kubeconfig string
	Selectors  []string
}

func NewRootCmd(probectl *controller.Controller) *cobra.Command {
	var (
		glob GlobalFlags
	)
	cmd := &cobra.Command{
		Use:           "vpp-probe COMMAND",
		Short:         "A CLI tool for debugging VPP instances",
		Long:          Logo,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if glob.Debug || os.Getenv("DEBUG") != "" {
				logrus.SetLevel(logrus.DebugLevel)
			}
			provider, err := setupProvider(glob)
			if err != nil {
				return err
			}
			return probectl.SetProvider(provider)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbeUI(probectl)
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolVarP(&glob.Debug, "debug", "D", false,
		"Enable debug mode")
	flags.StringVar(&glob.Env, "env", "",
		"Environment type in which VPP is running (local, kube)")

	// Kube flags
	flags.StringVar(&glob.Kubeconfig, "kubeconfig", "",
		"Path to kubeconfig, defaults to ~/.kube/config (or set via KUBECONFIG)")
	flags.StringSliceVarP(&glob.Selectors, "selector", "l", nil,
		"Label query (selector) to filter on, supports '='. (e.g. -l key1=val1,key2=val2)")

	AddCommands(cmd, probectl)

	return cmd
}

func AddCommands(cmd *cobra.Command, probectl *controller.Controller) {
	cmd.AddCommand(
	//NewDiscoverCmd(probectl),
	//NewTracerCmd(probectl),
	)
}

func runProbeUI(probectl *controller.Controller) error {
	app := termui.NewApp(probectl)
	return app.Run()
}
