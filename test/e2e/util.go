package e2e

import (
	"bytes"
	"flag"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	waitCreateCluster = time.Second * 90
	waitPodReady      = time.Second * 120
)

var (
	dumpDir = flag.String("dumpdir", "./logs/dumps", "Directory location for dumps")
)

func kubectl(t *testing.T, context string, args ...string) {
	if t != nil {
		t.Helper()
	}

	args = append([]string{
		"--context", context,
	}, args...)
	execCmd(t, "kubectl", args...)
}

func contextName(name string) string {
	return "kind-" + name
}

func createCluster(name string) {
	execCmd(nil, "kind", "create", "cluster", "--name", name, "--wait", waitCreateCluster.String())
}

func deleteCluster(name string) {
	execCmd(nil, "kind", "delete", "cluster", "--name", name)
}

func dumpData(name string) {
	kubectl(nil, contextName(name), "cluster-info", "dump", "--all-namespaces", "--output-directory", filepath.Join(*dumpDir, name))
}

func execCmd(t *testing.T, cmd string, args ...string) {
	if t != nil {
		t.Helper()
	}
	var stdout, stderr bytes.Buffer
	c := exec.Command(cmd, args...)
	c.Stdout = &stdout
	c.Stderr = &stderr
	if t != nil {
		t.Logf("[EXEC] %v", c)
	} else {
		log.Printf("[EXEC] %v", c)
	}
	err := c.Run()
	out := strings.TrimSpace(stdout.String())
	if t != nil {
		t.Logf("[STDOUT]\n%v\n-----", out)
	} else {
		log.Printf("[STDOUT] %v\n------", out)
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			ee.Stderr = stderr.Bytes()
		}
		if t == nil {
			log.Fatalf("%v: %s", err, stderr.Bytes())
		} else {
			t.Fatalf("%v: %s", err, stderr.Bytes())
		}
	}
}
