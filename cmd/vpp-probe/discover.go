package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gookit/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	vpp_interfaces "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"

	"go.ligato.io/vpp-probe/pkg/kube"
)

var discoverCmd = &cobra.Command{
	Use:     "discover",
	Aliases: []string{"disc", "find"},
	Short:   "Discover running VPP instances",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDiscover()
	},
}

func init() {
	discoverCmd.Flags().StringVar(&kubeconfigs, "kubeconfigs", "", "File or Directory with kubeconfigs")
	discoverCmd.Flags().StringSliceVarP(&queriesFlag, "query", "q", []string{}, "Queries for pods")
	discoverCmd.Flags().BoolVar(&extra, "extra", false, "Extra info")

	rootCmd.AddCommand(discoverCmd)
}

var (
	kubeconfigs string
	queriesFlag []string
	extra       bool
)

func loadConfigs(d string) ([]string, error) {
	kconfFmode, err := os.Stat(d)
	if err != nil {
		logrus.Errorf("Bad kubeconfig file/dir: %v", err)
		return nil, err
	}
	var configs []string
	if kconfFmode.IsDir() {
		dir, err := ioutil.ReadDir(d)
		if err != nil {
			return nil, err
		}
		for _, f := range dir {
			if f.IsDir() {
				continue
			}
			conf := path.Join(d, f.Name())
			configs = append(configs, conf)
			logrus.Debugf("found kubeconfig: %s", conf)
		}
	} else {
		configs = append(configs, d)
	}
	return configs, err
}

func parseQueries(qstrs []string) []kube.PodQuery {
	var queries []kube.PodQuery
	for _, q := range qstrs {
		query := kube.PodQuery{
			Label: q,
		}
		queries = append(queries, query)
	}
	return queries
}

func runDiscover() error {
	if kubeconfigs == "" {
		return fmt.Errorf("kubeconfigs directory not set")
	}
	configs, err := loadConfigs(kubeconfigs)
	if err != nil {
		return fmt.Errorf("loadConfigs failed: %w", err)
	}
	if len(configs) == 0 {
		return fmt.Errorf("no kubeconfigs found in %s", kubeconfigs)
	}
	logrus.Debug("%d kubeconfigs laoded..", len(configs))

	queries := parseQueries(queriesFlag)
	if len(queries) == 0 {
		return fmt.Errorf("at least one query neeeded")
	}
	logrus.Debugf("%d queries for filtering pods:", len(queries))
	for _, q := range queries {
		logrus.Debugf("- %v", q)
	}

	for _, config := range configs {
		kubectx, err := kube.NewKubeCtx(config)
		if err != nil {
			return fmt.Errorf("loading kube %s error: %v", config, err)
		}
		instances, err := discoverVppInstances(kubectx, queries)
		if err != nil {
			logrus.Errorf("cluster %s error: %v", kubectx.CurrentContext, err)
			continue
		}
		for _, instance := range instances {
			if err := updateInstanceInfo(instance); err != nil {
				logrus.Errorf("retrieving VPP info failed: %v", err)
			}
		}

		clr := color.LightCyan.Render
		fmt.Println()
		fmt.Println("====================================================================================================")
		fmt.Printf(" Context: %s - discovered %v VPP instances\n", clr(kubectx.CurrentContext), len(instances))
		fmt.Println("====================================================================================================")
		fmt.Println()
		for _, instance := range instances {
			fmt.Println("--------------------------------------------------")
			fmt.Printf(" Pod: %s Namespace: %v IP: %v (age: %v)\n", clr(instance.pod.Name), clr(instance.pod.Namespace), clr(instance.pod.IP), instance.pod.Age())
			fmt.Println("--------------------------------------------------")
			fmt.Println()
			printInstance(instance)
		}
	}
	return nil
}

type Pod struct {
	Cluster   string
	Namespace string
	Name      string
	IP        string
	Created   time.Time

	*kube.KubeCtx
}

func (p Pod) String() string {
	return fmt.Sprintf("Pod %v", p.Name)
}

func (p Pod) Age() time.Duration {
	return time.Since(p.Created).Round(time.Second)
}

func discoverVppInstances(kubectx *kube.KubeCtx, queries []kube.PodQuery) (list []*VppInstance, err error) {
	logrus.Infof("=> searching for matching pods in context %v", kubectx.CurrentContext)

	pods := kubectx.FindPods(queries)
	logrus.Infof("found %d pods", len(pods))

	for _, p := range pods {
		pod := Pod{
			KubeCtx:   kubectx,
			Cluster:   p.GetClusterName(),
			Name:      p.GetName(),
			Namespace: p.GetNamespace(),
			IP:        p.Status.PodIP,
			Created:   p.CreationTimestamp.Time,
		}
		instance, err := findVppInstanceInPod(kubectx, pod)
		if err != nil {
			logrus.Errorf("pod %s: %v", p.GetName(), err)
			continue
		}
		logrus.Infof("found instance: %v", instance.Version)

		instance.pod = &pod
		list = append(list, instance)
	}
	return
}

func findVppInstanceInPod(kubectx *kube.KubeCtx, pod Pod) (*VppInstance, error) {
	logrus.Infof("-> searching VPP instance in pod %s", pod)

	// retrieve VPP version
	out, err := kubectx.Exec(pod.Namespace, pod.Name, "", "vppctl show version")
	if err != nil {
		return nil, err
	}
	ver := strings.TrimSpace(out)

	instance := &VppInstance{
		Version: ver,
		Extra:   make(map[string]string),
	}
	return instance, nil
}

func printInstance(instance *VppInstance) {
	fmt.Printf(" Version: %s\n", color.FgLightBlue.Sprint(instance.Version))
	fmt.Println()

	printInterfacesTable(os.Stdout, instance.Interfaces)
	fmt.Println()
	fmt.Printf("%d vpp interfaces\n", len(instance.Interfaces))

	if len(instance.LinuxInterfaces) > 0 {
		fmt.Println()
		fmt.Printf("%d linux interfaces:\n", len(instance.LinuxInterfaces))
		for _, v := range instance.LinuxInterfaces {
			fmt.Printf(" - %v:\n", v.Value)
		}
	}
	fmt.Printf("\n")

	if extra {
		for k, v := range instance.Extra {
			val := color.FgLightBlue.Sprint(v)
			val = "\t" + strings.ReplaceAll(val, "\n", "\n\t")
			fmt.Printf("%s:\n\n%s\n", k, val)
			fmt.Println()
		}
		fmt.Println()
	}
}

func printInterfacesTable(out io.Writer, ifaces []*VppInterface) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 1, 8, 0, '\t', tabwriter.StripEscape)
	fmt.Fprintf(w, "IDX\t%v\t%v\t%v\t%v\tVRF\t%s\tDETAILS\t\n",
		escapeClr(color.LightWhite, "INTERFACE"), escapeClr(color.White, "TYPE"), escapeClr(color.White, "STATE"), escapeClr(color.White, "IP"), escapeClr(color.White, "MTU"))
	for _, iface := range ifaces {
		name := escapeClr(color.LightWhite, iface.Value.Name)
		state := escapeClr(color.Red, "down")
		if iface.Value.Enabled {
			state = escapeClr(color.Green, "up")
		}
		idx := iface.Metadata["SwIfIndex"]
		typ := escapeClr(color.LightMagenta, iface.Value.Type)
		ips := escapeClr(color.LightBlue, strings.Join(iface.Value.IpAddresses, " "))
		vrf := iface.Value.Vrf
		mtu := escapeClr(color.Yellow, iface.Value.Mtu)
		fmt.Fprintf(w, "%3v\t%v\t%v\t%v\v%v\t%v\t%v\t%v\t\n",
			idx, name, typ, state, ips, vrf, mtu, interfaceInfo(iface))
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	fmt.Fprint(out, buf.String())
}

func interfaceInfo(iface *VppInterface) string {
	switch iface.Value.Type {
	case vpp_interfaces.Interface_MEMIF:
		memif := iface.Value.GetMemif()
		var info string
		info += fmt.Sprintf("socket:%s ", escapeClr(color.LightYellow, memif.SocketFilename))
		if memif.Id > 0 {
			info += fmt.Sprintf("ID:%d ", memif.Id)
		}
		if memif.Master {
			info += fmt.Sprintf("master:%s ", escapeClr(color.LightYellow, memif.Master))
		}
		return info
	case vpp_interfaces.Interface_VXLAN_TUNNEL:
		vxlan := iface.Value.GetVxlan()
		var info string
		info += fmt.Sprintf("src:%s -> dst:%s (vni:%v)", escapeClr(color.LightYellow, vxlan.SrcAddress), escapeClr(color.LightYellow, vxlan.DstAddress), escapeClr(color.LightYellow, vxlan.Vni))
		return info
	case vpp_interfaces.Interface_TAP:
		tap := iface.Value.GetTap()
		return fmt.Sprintf("host_ifname:%s %v", escapeClr(color.LightYellow, iface.Metadata["TAPHostIfName"]), tap.String())
	case vpp_interfaces.Interface_AF_PACKET:
		afp := iface.Value.GetAfpacket()
		var info string
		info += fmt.Sprintf("host_if_name:%s", escapeClr(color.LightYellow, afp.HostIfName))
		return info
	}
	return fmt.Sprint(iface.Value.GetLink())
}
