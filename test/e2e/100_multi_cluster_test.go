package e2e

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"go.ligato.io/vpp-probe/cmd"
)

func TestMultiClusterTestSuite(t *testing.T) {
	t.Skip("skip multi cluster tests for now")
	suite.Run(t, &MultiClusterTestSuite{
		E2ETestSuite{
			resourcesDir: "./resources",
			clusters:     []string{*cluster1, *cluster2},
		},
	})
}

type MultiClusterTestSuite struct {
	E2ETestSuite
}

func (s *MultiClusterTestSuite) SetupSuite() {
	setup := func(kubectx string) {
		// setup topology
		kubectl(s.T(), kubectx, "apply", "-f", filepath.Join(s.resourcesDir, "vnf.yml"))
		time.Sleep(time.Second * 5)
		kubectl(s.T(), kubectx, "wait", "--for=condition=Ready", "pod/vpp-vnf1", "pod/vpp-vnf2", "pod/vpp-vswitch", fmt.Sprintf("--timeout=%v", waitPodReady))

		// copy configs to containers
		kubectl(s.T(), kubectx, "cp", filepath.Join(s.resourcesDir, "vnf1-config.yml"), "vpp-vnf1:/")
		kubectl(s.T(), kubectx, "cp", filepath.Join(s.resourcesDir, "vnf2-config.yml"), "vpp-vnf2:/")
		kubectl(s.T(), kubectx, "cp", filepath.Join(s.resourcesDir, "vswitch-config.yml"), "vpp-vswitch:/")
	}
	setup(s.kubectx(0))
	setup(s.kubectx(1))
}

func (s *MultiClusterTestSuite) TearDownSuite() {
	teardown := func(kubectx string) {
		// teardown topology
		kubectl(s.T(), kubectx, "delete", "-f", filepath.Join(s.resourcesDir, "vnf.yml"))
	}
	teardown(s.kubectx(0))
	teardown(s.kubectx(1))
}

func (s *MultiClusterTestSuite) SetupTest() {
	setup := func(kubectx string) {
		// configure VPPs
		kubectl(s.T(), kubectx, "exec", "-i", "vpp-vnf1", "--", "agentctl", "config", "update", "--replace", "/vnf1-config.yml")
		kubectl(s.T(), kubectx, "exec", "-i", "vpp-vnf2", "--", "agentctl", "config", "update", "--replace", "/vnf2-config.yml")
		kubectl(s.T(), kubectx, "exec", "-i", "vpp-vswitch", "--", "agentctl", "config", "update", "--replace", "/vswitch-config.yml")
	}
	setup(s.kubectx(0))
	setup(s.kubectx(1))
}

func (s *MultiClusterTestSuite) TearDownTest() {
	// cleanup after test
}

func (s *MultiClusterTestSuite) TestDiscover() {
	cli := s.setupProbeCli()

	discOpts := cmd.DiscoverOptions{
		IPsecAgg: true,
	}
	err := cmd.RunDiscover(cli, discOpts)
	s.NoError(err)
}

func (s *MultiClusterTestSuite) TestTopology() {
	cli := s.setupProbeCli()

	topoOpts := cmd.TopologyOptions{}

	err := cmd.RunTopology(cli, topoOpts)
	s.NoError(err)
}
