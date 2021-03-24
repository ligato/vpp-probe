package integration

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"go.ligato.io/vpp-probe/cmd"
	"go.ligato.io/vpp-probe/providers"
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

const DefaultVppAgentImage = "ligato/vpp-agent:v3.2.0"

type IntegrationSuite struct {
	suite.Suite

	vpp1          string
	vppAgentImage string
}

func TestDockerSuite(t *testing.T) {
	suite.Run(t, &DockerSuite{
		IntegrationSuite{
			vpp1:          "integration-test-vpp1",
			vppAgentImage: DefaultVppAgentImage,
		},
	})
}

type DockerSuite struct {
	IntegrationSuite
}

func (s *DockerSuite) SetupSuite() {
	execCmd(s.T(), "docker", "run", "--name="+s.vpp1, "-d", "-it", "--privileged", "-e=ETCD_CONFIG=disabled", "-e MICROSERVICE_LABEL=vpp1", s.vppAgentImage)
	time.Sleep(time.Second * 3)
}

func (s *DockerSuite) TearDownSuite() {
	execCmd(s.T(), "docker", "stop", "-t", "2", s.vpp1)
	execCmd(s.T(), "docker", "rm", "-f", s.vpp1)
}

func (s *DockerSuite) SetupTest() {
	execCmd(s.T(), "docker", "container", "ls", "--filter=name="+s.vpp1)
}

func (s *DockerSuite) TestMultiCommandCli() {
	cli, err := cmd.NewProbeCli()
	s.Require().NoError(err)

	var opts cmd.ProbeOptions
	opts.Env = providers.Docker
	opts.Queries = []string{"name=" + s.vpp1}

	cmd.InitOptions(cli, cmd.GlobalOptions{
		Debug:    true,
		LogLevel: "trace",
		Color:    "on",
	})

	err = cli.Initialize(opts)
	s.Require().NoError(err)

	err = cli.Client().DiscoverInstances(cli.Queries()...)
	s.Require().NoError(err)

	instances := cli.Client().Instances()
	if s.Len(instances, 1, "Expected single instance") {
		instance := instances[0]

		cmds := []string{
			"show version",
			"show int",
		}
		c := strings.Join(cmds, "\n")
		out, err := instance.RunCli(c)
		s.NoError(err, "RunCli should succeed")
		s.Contains(out, "local0")
	}
}
