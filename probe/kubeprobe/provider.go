package kubeprobe

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/pkg/kube"
	"go.ligato.io/vpp-probe/probe"
)

// Provider finds instances running in Kubernetes pods.
type Provider struct {
	Clients []*kube.Client
	Queries []PodQuery
}

func NewProvider(kubeconfig string, selector []string) (*Provider, error) {
	provider := &Provider{}

	for _, cfg := range contextConfigs(kubeconfig) {
		client, err := kube.NewClient(cfg)
		if err != nil {
			logrus.Warnf("loading client for context %s failed: %v", cfg, err)
			continue
		}
		info, err := client.GetVersionInfo()
		if err != nil {
			logrus.Warnf("getting version info for client %s failed: %v", client, err)
			continue
		}
		logrus.Infof("kube client %s version info: %v", client, info)
		provider.Clients = append(provider.Clients, client)
	}

	if len(provider.Clients) == 0 {
		return nil, fmt.Errorf("no available kube clients")
	}
	logrus.Debugf("loaded %d clients", len(provider.Clients))

	provider.Queries = parseQueries(selector)
	if len(provider.Queries) == 0 {
		return nil, fmt.Errorf("at least one selector neeeded")
	}

	return provider, nil
}

func (k *Provider) Discover(query ...interface{}) ([]probe.Handler, error) {
	var instances []probe.Handler

	for _, client := range k.Clients {
		logrus.Infof("-> searching in cluster %v", client.Cluster())

		pods, err := queryPods(client, k.Queries)
		if err != nil {
			logrus.Warnf("query pods error: %v", err)
			continue
		}

		for _, pod := range pods {
			instance := &Handler{
				Pod: pod,
			}
			logrus.Infof("found instance: %v", instance)
			instances = append(instances, instance)
		}
	}

	if len(instances) == 0 {
		return nil, fmt.Errorf("no VPP instances found")
	}

	return instances, nil
}

func contextConfigs(kubeconfig string) []*kube.Config {
	config := kube.NewConfig(kubeconfig)
	config.KubeConfig = kubeconfig
	var configs []*kube.Config
	for _, ctx := range config.Contexts() {
		cfg := kube.NewConfig(kubeconfig)
		cfg.Context = ctx
		configs = append(configs, cfg)
	}
	return configs
}

func queryPods(kubectx *kube.Client, queries []PodQuery) ([]*kube.Pod, error) {
	var list []*kube.Pod
	for _, q := range queries {
		logrus.Debugf("query pods: %+v", q)

		pods, err := kubectx.ListPods(q.Namespace, q.LabelSelector)
		if err != nil {
			logrus.Warnf("ListPods failed: %v", err)
			continue
		}
		if len(pods) == 0 {
			logrus.Debugf("no matching pods found")
			continue
		}
		logrus.Debugf("%d matching pods found", len(pods))

		list = append(list, pods...)
	}
	return list, nil
}

type PodQuery struct {
	Namespace     string
	Name          string
	LabelSelector string
}

func (q PodQuery) String() string {
	s := fmt.Sprintf("Label=%q ", q.LabelSelector)
	if q.Namespace != "" {
		s += fmt.Sprintf("Namespace=%q", q.Namespace)
	} else {
		s += fmt.Sprintf("Namespace=ALL")
	}
	return s
}

func parseQueries(qstrs []string) []PodQuery {
	var queries []PodQuery
	for _, q := range qstrs {
		query := PodQuery{
			LabelSelector: q,
		}
		queries = append(queries, query)
	}
	return queries
}
