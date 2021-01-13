package cmd

import (
	"github.com/go-stack/stack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/internal/ui"
)

func NewInspectorCmd(cli Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inspector",
		Aliases: []string{"inspect", "ui"},
		Short:   "Inspect VPP instances using terminal UI browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspector(cli)
		},
	}
	return cmd
}

func runInspector(cli Cli) error {
	defer func() {
		if err := recover(); err != nil {
			logrus.Errorf("PANIC: %+v\n%v", err, stack.Trace().String())
		}
	}()

	app := ui.NewApp(cli.Controller())
	app.RunDiscovery(cli.Queries()...)

	if err := app.Run(); err != nil {
		return err
	}
	return nil
}
