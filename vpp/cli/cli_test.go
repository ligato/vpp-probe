package vppcli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	live = flag.Bool("live", false, "Enable tests running with live VPP")
)

func init() {
	if os.Getenv("DEBUG_VPPCLI") != "" {
		logrus.SetLevel(logrus.TraceLevel)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	code := m.Run()
	os.Exit(code)
}

func TestUnexpectedBanner(t *testing.T) {
	if !*live {
		t.Skip("skip live tests (enable with --live)")
	}

	localcli := NewCmdExecutor("/usr/bin/vppctl")

	for i := 0; i < 1000; i++ {
		out, err := localcli.RunCli("show version")
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

const cliBanner = `    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# `

func TestStripBanner(t *testing.T) {
	const (
		expectOut = "show version"
	)

	testcli := NewCmdExecutor("echo", "-e", cliBanner)

	out, err := testcli.RunCli("show version")
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

func TestCleanup(t *testing.T) {
	const expectOut = "show int"

	output := fmt.Sprintf("%s%s\n", cliBanner, expectOut)
	t.Logf("output: %q", output)

	cleaned := CleanOutput([]byte(output))

	if strings.Contains(cleaned, "vpp#") {
		t.Fatalf("unexpected prompt in output: %q", cleaned)
	}
	if trim := strings.TrimSpace(cleaned); trim != expectOut {
		t.Fatalf("expected: %q, got: %q", expectOut, trim)
	}
}
