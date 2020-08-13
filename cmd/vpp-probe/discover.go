package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
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
	discoverCmd.Flags().StringVar(&kubeconfigs, "kubeconfigs", "", "Directory with kubeconfigs")
	discoverCmd.Flags().StringSliceVarP(&queriesFlag, "query", "q", []string{}, "Queries for pods")
	discoverCmd.Flags().BoolVar(&extra, "extra", false, "Extra info")
	rootCmd.AddCommand(discoverCmd)
}

var (
	kubeconfigs string
	queriesFlag []string
	extra       bool
)

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

	//var instances []VppInstance
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
			if err := updateInstanceInfo(kubectx, instance); err != nil {
				logrus.Errorf("retrieving VPP info failed: %v", err)
			}
		}

		clr := color.LightCyan.Render
		fmt.Println()
		fmt.Println("====================================================================================================")
		fmt.Printf(" Context: %s - discovered %v VPP instances\n", clr(kubectx.CurrentContext), len(instances))
		fmt.Println("====================================================================================================")
		fmt.Println()

		printInstances(instances)
	}

	return nil
}

func loadConfigs(d string) ([]string, error) {
	dir, err := ioutil.ReadDir(d)
	if err != nil {
		return nil, err
	}
	var configs []string
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		conf := path.Join(d, f.Name())
		configs = append(configs, conf)
		logrus.Debugf("found kubeconfig: %s", conf)
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

func printInstances(instances []*VppInstance) {
	clr := color.LightCyan.Render

	for _, instance := range instances {
		fmt.Println("--------------------------------------------------")
		fmt.Printf(" Pod: %s Namespace: %v IP: %v (age: %v)\n",
			clr(instance.Pod.Name), clr(instance.Pod.Namespace), clr(instance.Pod.IP), instance.Pod.Age())
		fmt.Println("--------------------------------------------------")
		fmt.Println()

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
}

func printInterfacesTable(out io.Writer, ifaces []*VppInterface) {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 0, '\t', tabwriter.StripEscape)
	// header
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
			idx, name, typ, state, ips, vrf, mtu, iface.Info())
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	fmt.Fprint(out, buf.String())
}

type Pod struct {
	Cluster   string
	Namespace string
	Name      string
	IP        string
	Created   time.Time
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

		instance.Pod = pod
		list = append(list, instance)
	}

	return
}

func findVppInstanceInPod(kubectx *kube.KubeCtx, pod Pod) (*VppInstance, error) {
	logrus.Infof("-> searching for VPP instance in pod %s", pod)

	// Get VPP version
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

func updateInstanceInfo(kubectx *kube.KubeCtx, instance *VppInstance) error {
	pod := instance.Pod

	runExtra := func(cmd string) {
		out, err := kubectx.Exec(pod.Namespace, pod.Name, "", "vppctl "+cmd)
		if err != nil {
			logrus.Warnf("pod %v: %v", pod.Name, err)
		}
		instance.Extra[cmd] = strings.TrimSpace(out)
	}

	// VPP interfaces
	dump, err := kubectx.Exec(pod.Namespace, pod.Name, "", "agentctl dump -f json vpp.interfaces")
	if err != nil {
		logrus.Warnf("pod %v: dump vpp interfaces failed: %v", pod.Name, err)
		//return nil, err
	} else {
		logrus.Debugf("dump: %q", dump)
		var list []VppInterface
		err = json.Unmarshal([]byte(dump), &list)
		if err != nil {
			return err
		}
		sortIfaces(list)
		var ifaces []*VppInterface
		for _, iface := range list {
			ifc := iface
			if ifc.Origin == 2 && strings.HasSuffix(ifc.Value.Name, "local0") {
				continue
			}
			ifaces = append(ifaces, &ifc)
		}
		instance.Interfaces = ifaces
		runExtra("show int")
		runExtra("show ha detail")
		runExtra("show ip fib")
		if hasIfaceType(ifaces, vpp_interfaces.Interface_MEMIF) {
			runExtra("show memif")
		}
		if hasIfaceType(ifaces, vpp_interfaces.Interface_VXLAN_TUNNEL) {
			runExtra("show vxlan tunnel")
		}
		if hasIfaceType(ifaces, vpp_interfaces.Interface_TAP) {
			runExtra("show tap")
		}
		runExtra("show err")
	}

	// Linux interfaces
	dump, err = kubectx.Exec(pod.Namespace, pod.Name, "", "agentctl dump -f json linux.interfaces.interface")
	if err != nil {
		logrus.Warnf("pod %v: dump linux interfaces failed: %v", pod.Name, err)
		//return nil, err
	} else {
		logrus.Debugf("dump: %q", dump)
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
