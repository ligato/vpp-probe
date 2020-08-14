package vppcli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	if os.Getenv("DEBUG_VPPCLI") != "" {
		logrus.SetLevel(logrus.DebugLevel)
	}
}

func TestVppctl(t *testing.T) {
	if testing.Short() {
		t.Skip("skip in short testing")
	}

	cli := VppCtl()

	for i := 0; i < 1000; i++ {
		out, err := cli.RunCli("show version")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%3d. output: %q", i, out)

		if strings.Contains(out, "vpp#") {
			t.Fatal("unexpected VPP prompt in output")
		}

		time.Sleep(time.Second / 10)
	}
}

func TestStripBanner(t *testing.T) {
	const cliBanner = `    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# `
	const expectOut = "show version"

	cli := RemoteCmd("echo", "-e", cliBanner)

	out, err := cli.RunCli("show version")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("output: %q", out)

	if strings.Contains(out, "vpp#") {
		t.Fatal("unexpected banner in output")
	}
	if strings.TrimSpace(out) != expectOut {
		t.Fatalf("expected: %q", expectOut)
	}
}
