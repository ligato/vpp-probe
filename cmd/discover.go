package cmd

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/vpp"
)

const discoverExample = `  # Discover VPP instances in Kubernetes pods
  vpp-probe discover -e kube

  # Discover VPP instances from multiple kubeconfig contexts in single run 
  vpp-probe discover -e kube --kubecontext="demo1,demo2"

  # Discover VPP instances in Docker containers
  vpp-probe discover -e docker

  # Discover local VPP instance
  vpp-probe discover`

type PodInfo struct {
	pinfo []string
}

type NodeInfo struct {
	node, ip string
	plist    []PodInfo
}

type ClusterInfo struct {
	cname string
	nlist []NodeInfo
}

type worker struct {
	ptype int /* 0 - client, 1 - nse, 2 - forwarder*/
	inf   string
}

//var topo []ClusterInfo

var topo map[string]ClusterInfo
var nbr map[string]string

//var clusterset = make(map[string]bool)
var nodeset = make(map[string]bool)
var nodedump = make(map[string]PodInfo)

type DiscoverOptions struct {
	Format string
}

func NewDiscoverCmd(cli Cli) *cobra.Command {
	var (
		opts DiscoverOptions
	)
	cmd := &cobra.Command{
		Use:   "discover [options]",
		Short: "Discover running VPP instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunDiscover(cli, opts)
		},
		Example: discoverExample,
	}
	flags := cmd.Flags()
	flags.StringVarP(&opts.Format, "format", "f", "", "Output format (json, yaml, go-template..)")
	return cmd
}

func RunDiscover(cli Cli, opts DiscoverOptions) error {
	// TODO: refactor this to run discovery and only print list of discovered
	//  instances and move retrieval of agent config (interfaces) to a separate
	//  command that will support selecting specific instance
	topo = make(map[string]ClusterInfo)
	nbr = make(map[string]string)

	if err := cli.Client().DiscoverInstances(cli.Queries()...); err != nil {
		return err
	}

	instances := cli.Client().Instances()
	logrus.Debugf("discovered %d vpp instances", len(instances))

	for _, instance := range instances {
		if instance.Agent() == nil {
			logrus.Debugf("agent not found for instance %v", instance.ID())
			continue
		}
		logrus.Debugf("- updating vpp info %+v: %v", instance.ID(), instance.Status())

		err := instance.Agent().UpdateInstanceInfo()
		if err != nil {
			logrus.Errorf("instance %v error: %v", instance.ID(), err)
			continue
		}

		if format := opts.Format; len(format) == 0 {
			printDiscoverTable(cli.Out(), instance)
		} else {
			if err := formatAsTemplate(cli.Out(), format, instance); err != nil {
				return err
			}
		}
	}

	PrintCorrelation(cli.Out())
	return nil
}

func printDiscoverTable(out io.Writer, instance *vpp.Instance) {
	printInstanceHeader(out, instance.Handler())

	w := prefixWriter(out, defaultPrefix)
	PrintInstance(w, instance)
	BldCorrelation(instance)
}

func printInstanceHeader(out io.Writer, handler probe.Handler) {
	metadata := handler.Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, instanceHeaderColor.Sprint(v))
	}

	var header []string

	switch metadata["env"] {
	case providers.Kube:
		header = []string{
			metaKey("pod"),
			metaKey("namespace"),
			metaKey("node"),
			metaKey("cluster"),
			metaKey("ip"),
		}
	case providers.Docker:
		header = []string{
			metaKey("container"),
			metaKey("image"),
			metaKey("id"),
		}
	case providers.Local:
		header = []string{
			metaKey("pid"),
			metaKey("id"),
		}
	default:
		for k := range metadata {
			header = append(header, metaKey(k))
		}
	}

	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, " %s\n", strings.Join(header, " | "))
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
}

func PrintInstance(out io.Writer, instance *vpp.Instance) {
	var buf bytes.Buffer

	config := instance.Agent().Config

	// Info
	{
		fmt.Fprintf(&buf, "VPP version: %s\n", noteColor.Sprint(instance.VersionInfo().Version))
	}
	fmt.Fprintln(&buf)

	// VPP
	{
		if len(config.VPP.Interfaces) > 0 {
			fmt.Fprintln(&buf, headerColor.Sprint("VPP"))
			w := prefixWriter(&buf, defaultPrefix)
			PrintVPPInterfacesTable(w, config)
		} else {
			fmt.Fprintln(&buf, nonAvailableColor.Sprint("No VPP interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	// Linux
	{
		if len(config.Linux.Interfaces) > 0 {
			fmt.Fprintln(&buf, headerColor.Sprint("Linux"))
			w := prefixWriter(&buf, defaultPrefix)
			PrintLinuxInterfacesTable(w, config)
		} else {
			fmt.Fprintln(&buf, nonAvailableColor.Sprint("No linux interfaces configured"))
		}
	}
	fmt.Fprintln(&buf)

	fmt.Fprint(out, color.ReplaceTag(buf.String()))
}

func BldCorrelation(instance *vpp.Instance) {

	var cl ClusterInfo
	var updatepods PodInfo

	metadata := instance.Handler().Metadata()

	metaKey := func(k string) string {
		v := metadata[k]
		return fmt.Sprintf("%s: %v", k, instanceHeaderColor.Sprint(v))
	}

	if metadata["env"] == providers.Kube {

		var cname string = strings.Split(metaKey("cluster"), ":")[1]
		var nname string = strings.Split(metaKey("node"), ":")[1]
		var nip string = strings.Split(metaKey("ip"), ":")[1]
		var pname string = strings.Split(metaKey("pod"), ":")[1]

		if value, ok := topo[cname]; ok {
			//fmt.Println("value: ", value)
			cl = value
		} else {
			//fmt.Println("key not found, adding new entry")
			cl.cname = cname
		}

		ndexists := nodeset[nname]

		if !ndexists {
			nodeset[nname] = true
			nd := NodeInfo{
				node: nname,
				ip:   nip,
			}
			cl.nlist = append(cl.nlist, nd)

			updatepods.pinfo = append(updatepods.pinfo, pname)
			nodedump[nname] = updatepods
		} else {
			updatepods = nodedump[nname]
			updatepods.pinfo = append(updatepods.pinfo, pname)
			nodedump[nname] = updatepods
		}
		topo[cname] = cl
	}

	// Testing interface
	cfg := instance.Agent().Config
	if len(cfg.VPP.Interfaces) > 0 {
		for _, v := range cfg.VPP.Interfaces {
			if v.Metadata["InternalName"] == defaultVppInterfaceName {
				continue
			}
			iface := v.Value

			var iname string = interfaceInternalName(v)
			var idesc string = iface.Name
			var ips []string = iface.IpAddresses
			//var ips string = interfaceIPs(iface.IpAddresses, 0)
			//var info string = vppInterfaceInfo(v, false)
			var info string = iface.GetMemif().SocketFilename

			//v.Value.GetMemif().SocketFilename

			logrus.Debugf("----------TJ------------")
			logrus.Debugf("Internal: %s -> Interface : %s \n", iname, idesc)
			logrus.Debugf("ips : %s\n", ips)
			logrus.Debugf("info : %s\n", info)
			//
			//cols := []string{iname, idesc, ips, info}
			//logrus.Debugf(strings.Join(cols, "\t"))

			//if strings.Contains(idesc, "helloworld") {
			//	nbr[updatepods.pinfo] = idesc
			//}

		}

	}

	//keys := map[string]int{}
	//for i, iface := range cfg.VPP.Interfaces {
	//	keys[iface.Value.Name] = i
	//}
	//
	//logrus.Debugf("!!!!vpp key dump!!!")
	//for k, val := range keys {
	//
	//	logrus.Debugf("Key: %s", k, "=>", "Element: %d", val)
	//}
	////

}

func PrintCorrelation(out io.Writer) {

	fmt.Fprintf(out, "\n\n")

	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")
	fmt.Fprintf(out, "Topology\n")
	fmt.Fprintln(out, "----------------------------------------------------------------------------------------------------------------------------------")

	for key, cluster := range topo {
		fmt.Fprintf(out, "Cluster : %s\n", key)
		for i, n := range cluster.nlist {
			fmt.Fprintf(out, "\t %d : Node : %s / IP: %s\n", i, n.node, n.ip)

			var npods PodInfo = nodedump[n.node]

			for i := 0; i < len(npods.pinfo); i++ {
				fmt.Fprintf(out, "\t\t Pod : %s\n", npods.pinfo[i])
				//if value, ok := nbr[npods.pinfo[i]]; ok {
				//	fmt.Println("value: ", value)
				//	fmt.Fprint(out, "\t\t\t\t\t\t Neighbors\n")
				//	if strings.Contains(value, "helloworld") {
				//		fmt.Fprintf(out, "\t\t\t\t\t\t <-> %s\n", value)
				//	}
				//} else {
				//	logrus.Debugf("key not found")
				//}

			}
		}
	}
}
