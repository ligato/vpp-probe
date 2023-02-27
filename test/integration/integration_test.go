package integration

import (
	"flag"
	"log"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

const (
	DefaultVppAgentImage = "ligato/vpp-agent:latest"
)

var (
	VppAgentImage string
)

func init() {
	flag.StringVar(&VppAgentImage, "agent-image", DefaultVppAgentImage, "Use custom vpp-agent image")

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
		log.Println("skipping integration tests in short mode")
		return
	}

	os.Exit(m.Run())
}

type IntegrationSuite struct {
	suite.Suite

	vpp1          string
	vppAgentImage string
	msLabel       string
}

func TestDockerSuite(t *testing.T) {
	suite.Run(t, &DockerSuite{
		IntegrationSuite{
			msLabel:       "vpp1",
			vpp1:          "integration-test-vpp1",
			vppAgentImage: VppAgentImage,
		},
	})
}

type DockerSuite struct {
	IntegrationSuite
}

func (s *DockerSuite) SetupSuite() {
	execCmd(s.T(), "docker", "run", "--name="+s.vpp1, "-d", "-it", "--privileged", "-e=ETCD_CONFIG=disabled", "-e=MICROSERVICE_LABEL="+s.msLabel, s.vppAgentImage)
	time.Sleep(time.Second * 3)
}

func (s *DockerSuite) TearDownSuite() {
	const stopTimeout = 2
	execCmd(s.T(), "docker", "stop", "-t", strconv.Itoa(stopTimeout), s.vpp1)
	//if !s.T().Failed() {
	execCmd(s.T(), "docker", "rm", "-f", s.vpp1)
	//}
}

func (s *DockerSuite) SetupTest() {
	execCmd(s.T(), "docker", "container", "ls", "--filter=name="+s.vpp1)
}
