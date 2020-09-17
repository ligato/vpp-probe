package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
	linux_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/linux/interfaces"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
	vpp_l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"

	"go.ligato.io/vpp-probe/internal/vppcli"
)

type VppInstance struct {
	Version         string
	Interfaces      []*VppInterface
	LinuxInterfaces []*LinuxInterface
	L2XConnects     []*VppL2XConnect
	Extra           map[string]string

	pod *Pod
}

func (vpp *VppInstance) String() string {
	var loc = "local"
	if pod := vpp.pod; pod != nil {
		loc = pod.String()
	}
	return fmt.Sprintf("%v", loc)
}

func (vpp *VppInstance) ExecCmd(cmd string, args ...string) (string, error) {
	if pod := vpp.pod; pod != nil {
		cmd += " " + strings.Join(args, " ")
		out, err := pod.KubeCtx.Exec(pod.Namespace, pod.Name, "", cmd)
		if err != nil {
			return "", fmt.Errorf("pod %v exec error: %v", pod.Name, err)
		}
		return strings.TrimSpace(out), nil
	}
	c := exec.Command(cmd, args...)
	out, err := c.Output()
	return string(out), err
}

func (vpp *VppInstance) RunCli(cmd string) (string, error) {
	if pod := vpp.pod; pod != nil {
		out, err := pod.KubeCtx.Exec(pod.Namespace, pod.Name, "", "vppctl "+cmd)
		if err != nil {
			return "", fmt.Errorf("pod %v: %v", pod.Name, err)
		}
		return strings.TrimSpace(out), nil
	}
	return vppcli.Run(cmd)
}

type LinuxInterface struct {
	Value    *linux_interfaces.Interface
	Key      string
	Metadata map[string]interface{}
	Origin   uint
}

type VppInterface struct {
	Value    *vpp_interfaces.Interface
	Key      string
	Metadata map[string]interface{}
	Origin   uint
}
type VppL2XConnect struct {
	Value    *vpp_l2.XConnectPair
	Key      string
	Metadata map[string]interface{}
	Origin   uint
}

func updateInstanceInfo(instance *VppInstance) error {
	runExtra := func(cmd string) {
		out, err := instance.RunCli(cmd)
		if err != nil {
			logrus.Warnf("instance %v: %v", instance, err)
		}
		instance.Extra[cmd] = strings.TrimSpace(out)
	}
	runExtra("show int")
	runExtra("show ha detail")
	runExtra("show ip fib")
	runExtra("show ip arp")
	runExtra("show err")

	// VPP interfaces
	dump, err := instance.ExecCmd("agentctl dump -f json vpp.interfaces")
	if err != nil {
		logrus.Warnf("instance %v: dump vpp interfaces failed: %v", instance, err)
	} else {
		logrus.Debugf("vpp interface dump: %q", dump)
		var list []VppInterface
		err = json.Unmarshal([]byte(dump), &list)
		if err != nil {
			return err
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Value.Type < list[j].Value.Type
		})
		var ifaces []*VppInterface
		for _, iface := range list {
			ifc := iface
			if ifc.Origin == 2 && strings.HasSuffix(ifc.Value.Name, "local0") {
				continue
			}
			ifaces = append(ifaces, &ifc)
		}
		instance.Interfaces = ifaces
	}
	if instance.Interfaces == nil || hasIfaceType(instance.Interfaces, vpp_interfaces.Interface_MEMIF) {
		runExtra("show memif")
	}
	if instance.Interfaces == nil || hasIfaceType(instance.Interfaces, vpp_interfaces.Interface_VXLAN_TUNNEL) {
		runExtra("show vxlan tunnel")
	}
	if instance.Interfaces == nil || hasIfaceType(instance.Interfaces, vpp_interfaces.Interface_TAP) {
		runExtra("show tap")
	}

	dump, err = instance.ExecCmd("agentctl dump -f json vpp.l2.xconnect")
	if err != nil {
		logrus.Warnf("instance %v: dump vpp l2 xconnect failed: %v", instance, err)
	} else {
		logrus.Debugf("vpp l2 xconnect dump: %q", dump)
		var list []VppL2XConnect
		err = json.Unmarshal([]byte(dump), &list)
		if err != nil {
			return err
		}

		var l2xconns []*VppL2XConnect
		for _, l2xconn := range list {
			xconn := l2xconn
			l2xconns = append(l2xconns, &xconn)
		}
		instance.L2XConnects = l2xconns
	}

	// Linux interfaces
	dump, err = instance.ExecCmd("agentctl dump -f json linux.interfaces.interface")
	if err != nil {
		logrus.Warnf("instance %v: dump linux interfaces failed: %v", instance, err)
	} else {
		logrus.Debugf("linux interface dump: %q", dump)
		var list []LinuxInterface
		err = json.Unmarshal([]byte(dump), &list)
		if err != nil {
			return err
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Value.Type < list[j].Value.Type
		})
		var ifaces []*LinuxInterface
		for _, iface := range list {
			ifc := iface
			if ifc.Origin == 2 && strings.HasSuffix(ifc.Value.Name, "local0") {
				continue
			}
			ifaces = append(ifaces, &ifc)
		}
		instance.LinuxInterfaces = ifaces
	}
	return nil
}

func hasIfaceType(ifaces []*VppInterface, typ vpp_interfaces.Interface_Type) bool {
	for _, iface := range ifaces {
		if iface.Value.Type == typ {
			return true
		}
	}
	return false
}
