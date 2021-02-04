package trace

import (
	"fmt"
	"strings"
)

// CLI is an interface for accessing VPP CLI.
type CLI interface {
	RunCli(cmd string) (string, error)
}

// Add starts tracing packets for nodes
func Add(cli CLI, numPackets int, nodes []string) error {
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes to trace")
	}
	if numPackets <= 0 {
		return fmt.Errorf("number of packets must be more than 0")
	}

	cmds := []string{
		"clear trace",
	}
	for _, node := range nodes {
		cmds = append(cmds, fmt.Sprintf("trace add %s %d", node, numPackets))
	}
	out, err := cli.RunCli(strings.Join(cmds, "\n"))
	if err != nil {
		return fmt.Errorf("trace command failed: %w\n%s", err, out)
	}

	return nil
}

// Show retrieves trace
func Show(cli CLI, maxPackets int) (string, error) {
	reply, err := cli.RunCli(fmt.Sprintf("show trace max %d", maxPackets))
	if err != nil {
		return "", err
	}

	return reply, nil
}
