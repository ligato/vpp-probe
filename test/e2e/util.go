package e2e

import (
	"log"
	"os"
	"os/exec"
	"testing"
	"time"
)

func createCluster(name string) {
	const waitDur = time.Minute
	mustRun(nil, "kind", "create", "cluster", "--name", name, "--wait", waitDur.String())
}

func deleteCluster(name string) {
	mustRun(nil, "kind", "delete", "cluster", "--name", name)
}

func mustRun(t *testing.T, cmd string, args ...string) {
	c := exec.Command(cmd, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if t != nil {
		t.Logf("RUN: %v\n", c)
	} else {
		log.Printf("RUN: %v\n", c)
	}
	err := c.Run()
	if err != nil {
		if t == nil {
			log.Fatalf("run failed: %v", err)
		} else {
			t.Fatalf("run failed: %v", err)
		}
	}
}
