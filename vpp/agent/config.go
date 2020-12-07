package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"go.ligato.io/vpp-agent/v3/pkg/models"
	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_ipsec "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/ipsec"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"

	"go.ligato.io/vpp-probe/probe"
)

const defaultVppInterfaceLocal0 = "local0"

type KVData struct {
	Key      string
	Metadata map[string]interface{}
	Origin   api.ValueOrigin
}

type LinuxInterface struct {
	KVData
	Value *linux_interfaces.Interface
}

type VppInterface struct {
	KVData
	Value *vpp_interfaces.Interface
}

type VppL2XConnect struct {
	KVData
	Value *vpp_l2.XConnectPair
}

type VppIPSecTunProtect struct {
	KVData
	Value *vpp_ipsec.TunnelProtection
}

type VppIPSecSA struct {
	KVData
	Value *vpp_ipsec.SecurityAssociation
}

func agentctlDumpData(handler probe.Host, format, model string) ([]byte, error) {
	dump, err := handler.ExecCmd("agentctl", "dump", "-f ", format, model)
	if err != nil {
		return nil, fmt.Errorf("dumping %s (format: %s) failed: %w", model, format, err)
	}
	logrus.Debugf("dumped %q (%d bytes)", model, len(dump))
	return []byte(dump), err
}

func agentctlDumpModel(handler probe.Host, model *models.KnownModel, v interface{}) error {
	dump, err := agentctlDumpData(handler, "json", model.Name())
	if err != nil {
		return err
	}
	if err := json.Unmarshal(dump, v); err != nil {
		return fmt.Errorf("unmarshaling %s dump (json) failed: %w", model, err)
	}
	return nil
}

func retrieveInterfacesVpp(handler probe.Handler) ([]VppInterface, error) {
	var list []VppInterface
	err := agentctlDumpModel(handler, vpp_interfaces.ModelInterface, &list)
	if err != nil {
		return nil, err
	}

	var ifaces []VppInterface
	for _, iface := range list {
		if iface.Origin == api.FromSB && strings.HasSuffix(iface.Value.Name, defaultVppInterfaceLocal0) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func retrieveInterfacesLinux(handler probe.Handler) ([]LinuxInterface, error) {
	var list []LinuxInterface
	err := agentctlDumpModel(handler, linux_interfaces.ModelInterface, &list)
	if err != nil {
		return nil, err
	}

	var ifaces []LinuxInterface
	for _, iface := range list {
		if iface.Origin == api.FromSB {
			continue
		}
		ifaces = append(ifaces, iface)
	}

	return ifaces, nil
}

func retrieveL2XConnects(handler probe.Handler) ([]VppL2XConnect, error) {
	var list []VppL2XConnect
	err := agentctlDumpModel(handler, vpp_l2.ModelXConnectPair, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func retrieveIPSecTunProtects(handler probe.Handler) ([]VppIPSecTunProtect, error) {
	var list []VppIPSecTunProtect

	err := agentctlDumpModel(handler, vpp_ipsec.ModelTunnelProtection, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func retrieveIPSecSAs(handler probe.Handler) ([]VppIPSecSA, error) {
	var list []VppIPSecSA
	err := agentctlDumpModel(handler, vpp_ipsec.ModelSecurityAssociation, &list)
	if err != nil {
		return nil, err
	}

	return list, nil
}
