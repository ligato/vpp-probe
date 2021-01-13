package e2e

import (
	"flag"
	"log"
	"os"
	"testing"
)

var (
	doSetup    = flag.Bool("setup", true, "Run setup of clusters")
	noTeardown = flag.Bool("noteardown", false, "Skip teardown of clusters")
)

func TestMain(m *testing.M) {
	flag.Parse()

	if testing.Short() {
		log.Println("skipping e2e tests in short mode")
		return
	}

	os.Exit(RunTests(m.Run))
}

func RunTests(r func() int) int {
	if *doSetup {
		Setup()
	} else {
		log.Println("# skipping setup of clusters")
	}

	if !*noTeardown {
		defer Teardown()
	} else {
		defer log.Println("# skipping teardown of clusters")
	}

	return r()
}

func Setup() {
	log.Println("======[ SETUP ]======")
	defer log.Println("---------------------")

	createCluster("c1")
}

func Teardown() {
	log.Println("-----[ TEARDOWN ]-----")
	defer log.Println("======================")

	deleteCluster("c1")
}
