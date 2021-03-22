package integration

import (
	"log"
	"os"
	"os/exec"
	"testing"
)

func execCmd(t *testing.T, cmd string, args ...string) {
	t.Helper()

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
