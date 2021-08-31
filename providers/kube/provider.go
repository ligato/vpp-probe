package kube

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"go.ligato.io/vpp-probe/probe"
	"go.ligato.io/vpp-probe/providers"
	"go.ligato.io/vpp-probe/providers/kube/client"
)

// Provider finds instances running in Kubernetes pods.
type Provider struct {
	client *client.Client
}

func NewProvider(kubeconfig string, context string) (*Provider, error) {
	cfg := client.NewConfigWith(kubeconfig, context)

	c, err := client.NewClient(cfg)
	if err != nil {
		logrus.Debugf("loading client for context %v failed: %v", context, err)
		return nil, err
	}

	provider := &Provider{
		client: c,
	}

	if err := provider.Ping(); err != nil {
		return nil, err
	}

	return provider, nil
}

func (p *Provider) Ping() error {
	logrus.Tracef("pinging kube provider %v", p.client)

	info, err := p.client.GetVersionInfo()
	if err != nil {
		logrus.Warnf("getting version info for client %v failed: %v", p.client, err)
		return err
	}

	logrus.Debugf("client %s version info: %v", p.client, info)

	return nil
}

func (p *Provider) Env() string {
	return providers.Kube
}

func (p *Provider) Name() string {
	return fmt.Sprintf("%v", p.client.String())
}

func (p *Provider) Query(params ...map[string]string) ([]probe.Handler, error) {
	queries, err := parseQueryParams(params)
	if err != nil {
		return nil, err
	}

	// force single empty query by default
	if len(queries) == 0 {
		queries = []PodQuery{{}}
	}

	logrus.Debugf("-> query %q in %v (cluster %v)", params, p.client, p.client.Cluster())

	pods, err := queryPods(p.client, queries)
	if err != nil {
		return nil, fmt.Errorf("query pods error: %w", err)
	}

	if len(pods) == 0 {
		return nil, fmt.Errorf("no pods queried")
	}

	logrus.Debugf("queried %d pods", len(pods))

	var handlers []probe.Handler
	for _, pod := range pods {
		node, err := p.client.GetNode(pod.NodeName)
		if err != nil {
			logrus.Errorf("Unable to get node %s for pod %s: %v", pod.NodeName, pod.Name, err)
		} else {
			pod.Node = node
		}
		handlers = append(handlers, NewHandler(pod))
	}

	return handlers, nil
}

func queryPods(kubectx *client.Client, queries []PodQuery) ([]*client.Pod, error) {
	var list []*client.Pod
	for _, q := range queries {
		logrus.Debugf("query pods: %+v", q)

		if q.Name != "" {
			pod, err := kubectx.GetPod(q.Namespace, q.Name)
			if err != nil {
				logrus.Warnf("GetPod failed: %v", err)
				continue
			}
			logrus.Debugf("matching pod found")

			list = append(list, pod)
		} else {
			pods, err := kubectx.ListPods(q.Namespace, q.LabelSelector, q.FieldSelector)
			if err != nil {
				logrus.Warnf("ListPods failed: %v", err)
				continue
			}
			if len(pods) == 0 {
				logrus.Infof("no matching pods found for query %v", q)
				continue
			}
			logrus.Debugf("%d matching pods found", len(pods))

			list = append(list, pods...)
		}
	}
	return list, nil
}

func parseQueryParams(listParams []map[string]string) ([]PodQuery, error) {
	var queries []PodQuery
	for _, params := range listParams {
		if params == nil {
			return nil, fmt.Errorf("invalid params: %q", params)
		}
		query := newPodQuery(params)
		queries = append(queries, query)
	}
	return queries, nil
}

type PodQuery struct {
	Name          string
	Namespace     string
	LabelSelector string
	FieldSelector string
}

func newPodQuery(params map[string]string) PodQuery {
	name := params["name"]
	if pod, ok := params["pod"]; ok && pod != "" {
		name = pod
	}
	return PodQuery{
		Name:          name,
		Namespace:     params["namespace"],
		LabelSelector: params["label"],
		FieldSelector: params["field"],
	}
}

func (q PodQuery) String() string {
	var s string
	if q.Namespace != "" {
		s += fmt.Sprintf("Namespace=%q", q.Namespace)
	}
	if q.Name != "" {
		s = fmt.Sprintf("Name=%q ", q.Name)
	} else {
		if q.LabelSelector != "" {
			s += fmt.Sprintf("Label=%q ", q.LabelSelector)
		}
		if q.FieldSelector != "" {
			s += fmt.Sprintf("Field=%q ", q.FieldSelector)
		}
	}
	return s
}
