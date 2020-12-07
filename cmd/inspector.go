package cmd

import (
	"github.com/go-stack/stack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/internal/ui"
)

func inspectorCmd(glob *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inspector",
		Aliases: []string{"inspect"},
		Short:   "Inspect VPP instances using terminal UI browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspector(*glob)
		},
	}
	return cmd
}

func runInspector(glob Flags) error {
	defer func() {
		if err := recover(); err != nil {
			logrus.Errorf("PANIC: %+v\n%v", err, stack.Trace().String())
		}
	}()

	logrus.Infof("🔭 Probe starting up..")

	ctl, err := SetupController(glob)
	if err != nil {
		return err
	}

	logrus.Infof("✅ Probe ready! Opening UI app..")

	app := ui.NewApp(ctl)
	app.RunDiscovery(glob.Queries...)

	if err := app.Run(); err != nil {
		return err
	}
	return nil
}
