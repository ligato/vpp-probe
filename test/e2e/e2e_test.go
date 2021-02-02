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
)

func init() {
	log.SetFlags(0)
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:               true,
		EnvironmentOverrideColors: true,
	})
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
		defer Teardown()
	} else {
		log.Println("# skipping setup of clusters")
	}

	return run()
}

type E2ETestSuite struct {
	suite.Suite

	kubectx string
}

type MultiClusterTestSuite struct {
	suite.Suite

	kubectxA string
	kubectxB string
}

func Setup() {
	log.Println("============== [ SETUP CLUSTERS ] ==============")
	defer log.Println("---------------------")

	createCluster("c1")
}

func Teardown() {
	log.Println("-----[ TEARDOWN CLUSTERS ]-----")
	defer log.Println("======================")

	deleteCluster("c1")
}
