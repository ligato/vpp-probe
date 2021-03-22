package e2e

import (
	"flag"
	"log"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

var (
	doSetup = flag.Bool("setup", true, "Setup clusters for tests")
	doTest  = flag.Bool("test", true, "Run tests")
)

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:               true,
		EnvironmentOverrideColors: true,
	})
	logrus.SetOutput(os.Stdout)
}

func TestMain(m *testing.M) {
	flag.Parse()

	if testing.Short() {
		log.Println("skipping e2e tests in short mode")
		return
	}

	os.Exit(RunTests(m.Run))
}

func RunTests(run func() int) int {
	if *doSetup {
		Setup()
	} else {
		log.Println("# skipping setup")
	}

	if !*doTest {
		log.Println("# skipping test")
		return 0
	}

	if *doSetup {
		defer Teardown()
	}

	return run()
}

type E2ETestSuite struct {
	suite.Suite

	resourcesDir string
	kubectx      string
}

func Setup() {
	log.Println("---------------------------------------")
	log.Println("============== [ SETUP ] ==============")
	log.Println("---------------------------------------")
	defer log.Println("---------------------------------------")

	createCluster("c1")
}

func Teardown() {
	log.Println("---------------------------------")
	log.Println("========= [ TEARDOWN ] ==========")
	log.Println("---------------------------------")
	defer log.Println("--------------------------------")

	deleteCluster("c1")
}
