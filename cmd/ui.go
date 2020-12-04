package cmd

import (
	"github.com/go-stack/stack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/internal/ui"
)

func uiCmd(glob *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUI(*glob)
		},
	}
	return cmd
}

func runUI(glob Flags) error {
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
