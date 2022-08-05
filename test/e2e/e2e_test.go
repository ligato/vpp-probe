package e2e

import (
	"flag"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"go.ligato.io/vpp-probe/cmd"
)

var (
	doSetup  = flag.Bool("setup", true, "Setup clusters for tests")
	doTest   = flag.Bool("test", true, "Run tests")
	cluster1 = flag.String("cluster1", "c1", "Name of cluster 1")
	cluster2 = flag.String("cluster2", "c2", "Name of cluster 2")
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

func Setup() {
	t := time.Now()

	log.Println("---------------------------------------")
	log.Println("============== [ SETUP ] ==============")
	log.Println("---------------------------------------")
	defer log.Printf("--------------- setup done (took %.3f sec) ---------------", time.Since(t).Seconds())

	createCluster(*cluster1)
	createCluster(*cluster2)
}

func Teardown() {
	t := time.Now()

	log.Println("---------------------------------")
	log.Println("========= [ TEARDOWN ] ==========")
	log.Println("---------------------------------")
	defer log.Printf("--------------- teardown done (took %.3f sec) ---------------", time.Since(t).Seconds())

	deleteCluster(*cluster1)
	deleteCluster(*cluster2)
}

type E2ETestSuite struct {
	suite.Suite

	resourcesDir string
	clusters     []string
}

func (s *E2ETestSuite) setupProbeCli() *cmd.ProbeCli {
	cli, err := cmd.NewProbeCli()
	s.NoError(err)

	var kubeCtxs []string
	for _, cluster := range s.clusters {
		kubeCtxs = append(kubeCtxs, contextName(cluster))
	}

	var opts cmd.ProbeOptions
	opts.Kube.Context = strings.Join(kubeCtxs, ",")

	err = cli.Initialize(opts)
	s.NoError(err)

	return cli
}

func (s *E2ETestSuite) kubectx(i int) string {
	return contextName(s.clusters[i])
}
