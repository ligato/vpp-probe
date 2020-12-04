package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/internal/version"
)

func versionCmd() *cobra.Command {
	var (
		short bool
	)
	cmd := cobra.Command{
		Use:   "version",
		Short: "Print version info",
		Run: func(cmd *cobra.Command, args []string) {
			printVersion(short)
		},
	}
	cmd.PersistentFlags().BoolVarP(&short, "short", "s", false, "Prints version info in short format")
	return &cmd
}

func printVersion(short bool) {
	if short {
		fmt.Println(version.String())
	} else {
		fmt.Println(version.Verbose())
	}
}
