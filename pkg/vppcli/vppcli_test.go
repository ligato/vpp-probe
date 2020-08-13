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
	for i := 0; i < 1000; i++ {
		out, err := Run("show version")
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

const weirdOutput = "\r" + `    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# `
