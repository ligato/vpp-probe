package e2e

import (
	"log"
	"os"
	"os/exec"
	"testing"
	"time"
)

const (
	waitCreateCluster = time.Minute
)

func kubectl(t *testing.T, context string, args ...string) {
	t.Helper()

	args = append([]string{
		"--context", context,
	}, args...)
	execCmd(t, "kubectl", args...)
}

func createCluster(name string) {
	execCmd(nil, "kind", "create", "cluster", "--name", name, "--wait", waitCreateCluster.String())
}

func deleteCluster(name string) {
	execCmd(nil, "kind", "delete", "cluster", "--name", name)
}

func execCmd(t *testing.T, cmd string, args ...string) {
	if t != nil {
		t.Helper()
	}

	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if t != nil {
		t.Logf("[EXEC] %v", c)
	} else {
		log.Printf("[EXEC] %v", c)
	}
	if err := c.Run(); err != nil {
		if t == nil {
			log.Fatalf("ERROR: %v", err)
		} else {
			t.Fatalf("ERROR: %v", err)
		}
	}
}
