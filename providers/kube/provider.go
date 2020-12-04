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

	context string
}

func NewProvider(kubeconfig string, context string) (*Provider, error) {
	cfg := client.NewConfig(kubeconfig)
	cfg.Context = context

	c, err := client.NewClient(cfg)
	if err != nil {
		logrus.Warnf("loading clientl for context %v failed: %v", cfg.Context, err)
		return nil, err
	}

	info, err := c.GetVersionInfo()
	if err != nil {
		logrus.Warnf("getting version info for client %v failed: %v", c, err)
		return nil, err
	}

	logrus.Infof("kube client %s version info: %v", c, info)

	provider := &Provider{
		client: c,
	}

	return provider, nil
}

func (p *Provider) Env() probe.Env {
	return providers.Kube
}

func (p *Provider) Name() string {
	return fmt.Sprintf("kube::%v", p.client.String())
}

func (p *Provider) Query(params ...map[string]string) ([]probe.Handler, error) {
	queries, err := parseQueryParams(params)
	if err != nil {
		return nil, err
	}

	c := p.client
	logrus.Infof("-> query %q in %v (cluster %v)", params, c.String(), c.Cluster())

	pods, err := queryPods(c, queries)
	if err != nil {
		return nil, fmt.Errorf("query pods error: %w", err)
	}

	logrus.Infof("found %d pods", len(pods))

	var handlers []probe.Handler
	for _, pod := range pods {
		handler := NewHandler(pod)
		handlers = append(handlers, handler)
	}

	if len(handlers) == 0 {
		return nil, fmt.Errorf("no instances found")
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
			logrus.Debugf("1 matching pod found")
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
	return PodQuery{
		Name:          params["name"],
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

/*func parseQueries(qstrs []string) []PodQuery {
	var queries []PodQuery
	for _, q := range qstrs {
		query := PodQuery{
			LabelSelector: q,
		}
		queries = append(queries, query)
	}
	return queries
}*/
