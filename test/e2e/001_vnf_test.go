package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gotest.tools/assert"

	"go.ligato.io/vpp-probe/client"
	"go.ligato.io/vpp-probe/providers/kube"
)

type VnfTestSuite struct {
	suite.Suite

	cluster string
}

func (suite *VnfTestSuite) SetupSuite() {
	t := suite.T()

	// setup topology
	mustRun(t, "kubectl", "--context", "kind-c1", "apply", "-f", "../resources/vnf.yml")
	time.Sleep(time.Second * 5)
	mustRun(t, "kubectl", "--context", "kind-c1", "wait", "--for=condition=Ready", "pod/vpp-vnf1", "pod/vpp-vnf2", "pod/vpp-vswitch", "--timeout=90s")

	// copy configs to containers
	mustRun(t, "kubectl", "--context", "kind-c1", "cp", "../resources/vnf1-config.yml", "vpp-vnf1:/")
	mustRun(t, "kubectl", "--context", "kind-c1", "cp", "../resources/vnf2-config.yml", "vpp-vnf2:/")
	mustRun(t, "kubectl", "--context", "kind-c1", "cp", "../resources/vswitch-config.yml", "vpp-vswitch:/")
}

func (suite *VnfTestSuite) TearDownSuite() {
	t := suite.T()

	mustRun(t, "kubectl", "--context", "kind-c1", "delete", "-f", "../resources/vnf.yml")
}

func (suite *VnfTestSuite) SetupTest() {
	t := suite.T()

	mustRun(t, "kubectl", "--context", "kind-c1", "exec", "-i", "vpp-vnf1", "--", "agentctl", "config", "update", "--replace", "/vnf1-config.yml")
	mustRun(t, "kubectl", "--context", "kind-c1", "exec", "-i", "vpp-vnf2", "--", "agentctl", "config", "update", "--replace", "/vnf2-config.yml")
	mustRun(t, "kubectl", "--context", "kind-c1", "exec", "-i", "vpp-vswitch", "--", "agentctl", "config", "update", "--replace", "/vswitch-config.yml")
}

func (suite *VnfTestSuite) TestDiscover() {
	t := suite.T()

	p, err := kube.NewProvider("", "kind-c1")
	if err != nil {
		t.Fatal(err)
	}

	c := client.NewClient()
	if err := c.AddProvider(p); err != nil {
		t.Fatal(err)
	}

	handlers, err := p.Query(map[string]string{"label": "app=vpp"})
	require.NoError(t, err)
	assert.Equal(t, 3, len(handlers))

	for _, h := range handlers {
		t.Logf("- %v: %+v", h.ID(), h.Metadata())
	}
}

func TestVnfTestSuite(t *testing.T) {
	suite.Run(t, new(VnfTestSuite))
}
