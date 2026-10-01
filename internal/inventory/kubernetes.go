// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

// In-cluster service account (Kubernetes mounts it into every pod).
var (
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Kubernetes reads one cluster with GET list calls only: nodes, pods,
// replica sets, deployments, stateful sets, daemon sets, services and
// ingresses. The response structs below declare only the fields used, so
// everything else (env, args, volumes, annotations…) is never decoded; labels
// and selectors are used in memory to join objects and never sent.
type Kubernetes struct {
	cluster       string
	base          string
	token         string
	includeSystem bool
	http          *http.Client
}

func NewKubernetes(c config.KubernetesCollector) (*Kubernetes, error) {
	cluster := strings.TrimSpace(c.Cluster)
	if cluster == "" || len(cluster) > 128 {
		return nil, errors.New("kubernetes: cluster (a name for InfraMole) is required")
	}
	rawURL, tokenFile, caFile := c.URL, c.TokenFile, c.CAFile
	var token string
	if c.InCluster {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("kubernetes: inCluster is set but the agent is not running in a pod")
		}
		rawURL = "https://" + net.JoinHostPort(host, port)
		if caFile == "" {
			caFile = inClusterCAFile
		}
		b, err := os.ReadFile(inClusterTokenFile) // projected by Kubernetes, rotated: re-read each run
		if err != nil {
			return nil, fmt.Errorf("kubernetes: service account token: %w", err)
		}
		token = strings.TrimSpace(string(b))
	} else {
		var err error
		if token, err = readSecretFile("kubernetes", "tokenFile", tokenFile); err != nil {
			return nil, err
		}
	}
	u, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || u.Host == "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("kubernetes: url must be https://host[:port] without credentials")
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("kubernetes: caFile has no PEM certificates")
		}
		tlsConf.RootCAs = pool
	case c.InsecureSkipVerify:
		tlsConf.InsecureSkipVerify = true // only settable in the local config file
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConf
	return &Kubernetes{
		cluster: cluster, base: u.String(), token: token, includeSystem: c.IncludeSystemNamespaces,
		http: &http.Client{
			Timeout: requestTimeout, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type k8sMeta struct {
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type k8sNode struct {
	Metadata k8sMeta `json:"metadata"`
	Status   struct {
		Addresses []struct {
			Type    string `json:"type"`
			Address string `json:"address"`
		} `json:"addresses"`
		NodeInfo struct {
			KubeletVersion string `json:"kubeletVersion"`
			OSImage        string `json:"osImage"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

type k8sPod struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type k8sWorkload struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		Replicas *int `json:"replicas"`
		Template struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas          int `json:"readyReplicas"`
		NumberReady            int `json:"numberReady"`
		DesiredNumberScheduled int `json:"desiredNumberScheduled"`
	} `json:"status"`
}

type k8sService struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		Type        string            `json:"type"`
		Selector    map[string]string `json:"selector"`
		ExternalIPs []string          `json:"externalIPs"`
		Ports       []struct {
			Port int `json:"port"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP string `json:"ip"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type k8sBackend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type k8sIngress struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		DefaultBackend *k8sBackend `json:"defaultBackend"`
		Rules          []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Backend k8sBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

// list GETs a collection, following `continue` tokens.
func list[T any](ctx context.Context, k *Kubernetes, path string, optional bool) ([]T, error) {
	var out []T
	cont := ""
	for page := 0; page < 50; page++ {
		u := k.base + path + "?limit=500"
		if cont != "" {
			u += "&continue=" + url.QueryEscape(cont)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+k.token)
		req.Header.Set("Accept", "application/json")
		res, err := k.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
		res.Body.Close()
		switch {
		case err != nil:
			return nil, fmt.Errorf("kubernetes: %w", err)
		case res.StatusCode == http.StatusUnauthorized:
			return nil, errors.New("kubernetes: 401 — the token was rejected")
		case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusNotFound:
			if optional {
				return nil, nil
			}
			return nil, fmt.Errorf("kubernetes: %s on %s (check the ClusterRole: get/list on it)", res.Status, path)
		case res.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("kubernetes: unexpected %s on %s", res.Status, path)
		case len(body) > maxResponseBytes:
			return nil, errors.New("kubernetes: response too large")
		}
		var doc struct {
			Items    []T `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("kubernetes: invalid JSON: %w", err)
		}
		out = append(out, doc.Items...)
		if cont = doc.Metadata.Continue; cont == "" {
			break
		}
	}
	return out, nil
}

// Collect lists the objects and joins them into nodes and workloads.
func (k *Kubernetes) Collect(ctx context.Context) (*protocol.Kubernetes, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	nodes, err := list[k8sNode](ctx, k, "/api/v1/nodes", false)
	if err != nil {
		return nil, err
	}
	pods, err := list[k8sPod](ctx, k, "/api/v1/pods", false)
	if err != nil {
		return nil, err
	}
	rs, err := list[k8sWorkload](ctx, k, "/apis/apps/v1/replicasets", false)
	if err != nil {
		return nil, err
	}
	kinds := map[string][]k8sWorkload{}
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
		items, err := list[k8sWorkload](ctx, k, "/apis/apps/v1/"+strings.ToLower(kind)+"s", false)
		if err != nil {
			return nil, err
		}
		kinds[kind] = items
	}
	services, err := list[k8sService](ctx, k, "/api/v1/services", false)
	if err != nil {
		return nil, err
	}
	ingresses, _ := list[k8sIngress](ctx, k, "/apis/networking.k8s.io/v1/ingresses", true) // optional
	inv := k8sInventory(k.cluster, nodes, pods, rs, kinds, services, ingresses)
	if !k.includeSystem {
		kept := inv.Workloads[:0]
		for _, w := range inv.Workloads {
			if !systemNamespaces[w.Namespace] {
				kept = append(kept, w)
			}
		}
		inv.Workloads = kept
	}
	return inv, nil
}

var systemNamespaces = map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}

func k8sInventory(cluster string, nodes []k8sNode, pods []k8sPod, replicaSets []k8sWorkload, kinds map[string][]k8sWorkload, services []k8sService, ingresses []k8sIngress) *protocol.Kubernetes {
	out := &protocol.Kubernetes{Cluster: cluster, CollectedAt: time.Now().UTC(), Nodes: []protocol.K8sNode{}, Workloads: []protocol.K8sWorkload{}}
	for _, n := range nodes {
		if n.Metadata.Name == "" || len(out.Nodes) >= 500 {
			continue
		}
		var ips []string
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" || a.Type == "ExternalIP" {
				ips = append(ips, a.Address)
			}
		}
		ips = usableIPs(ips)
		if len(ips) > 8 {
			ips = ips[:8]
		}
		if ips == nil {
			ips = []string{}
		}
		out.Nodes = append(out.Nodes, protocol.K8sNode{
			Name: clip(n.Metadata.Name, 253), IPs: ips,
			Version: clip(n.Status.NodeInfo.KubeletVersion, 64), OS: clip(n.Status.NodeInfo.OSImage, 128),
		})
	}

	nodeIPs := map[string]bool{}
	for _, n := range out.Nodes {
		for _, ip := range n.IPs {
			nodeIPs[ip] = true
		}
	}

	// ReplicaSet → Deployment.
	rsOwner := map[string]string{}
	for _, r := range replicaSets {
		for _, o := range r.Metadata.OwnerReferences {
			if o.Kind == "Deployment" {
				rsOwner[r.Metadata.Namespace+"/"+r.Metadata.Name] = o.Name
			}
		}
	}
	// Workload "Kind/ns/name" → nodes where its pods run.
	podNodes := map[string]map[string]bool{}
	for _, p := range pods {
		if p.Spec.NodeName == "" || (p.Status.Phase != "Running" && p.Status.Phase != "Pending") {
			continue
		}
		for _, o := range p.Metadata.OwnerReferences {
			kind, name := o.Kind, o.Name
			if kind == "ReplicaSet" {
				if d := rsOwner[p.Metadata.Namespace+"/"+name]; d != "" {
					kind, name = "Deployment", d
				}
			}
			key := kind + "/" + p.Metadata.Namespace + "/" + name
			if podNodes[key] == nil {
				podNodes[key] = map[string]bool{}
			}
			podNodes[key][p.Spec.NodeName] = true
		}
	}

	type wl struct {
		out    protocol.K8sWorkload
		labels map[string]string
	}
	var all []*wl
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
		for _, w := range kinds[kind] {
			if w.Metadata.Name == "" || len(all) >= protocol.MaxInventoryItems {
				continue
			}
			item := protocol.K8sWorkload{
				Namespace: clip(w.Metadata.Namespace, 253), Name: clip(w.Metadata.Name, 253), Kind: kind,
				Images: []string{}, Nodes: []string{}, Services: []protocol.K8sService{},
			}
			for _, c := range w.Spec.Template.Spec.Containers {
				if c.Image != "" && len(item.Images) < 16 && !containsString(item.Images, clip(c.Image, 512)) {
					item.Images = append(item.Images, clip(c.Image, 512))
				}
			}
			if kind == "DaemonSet" {
				desired, ready := w.Status.DesiredNumberScheduled, w.Status.NumberReady
				item.Replicas, item.Ready = &desired, &ready
			} else if w.Spec.Replicas != nil {
				replicas, ready := *w.Spec.Replicas, w.Status.ReadyReplicas
				item.Replicas, item.Ready = &replicas, &ready
			}
			for n := range podNodes[kind+"/"+w.Metadata.Namespace+"/"+w.Metadata.Name] {
				item.Nodes = append(item.Nodes, clip(n, 253))
			}
			sort.Strings(item.Nodes)
			all = append(all, &wl{out: item, labels: w.Spec.Template.Metadata.Labels})
		}
	}

	// Service → workloads whose pod labels match its selector.
	svcTargets := map[string][]*wl{}
	for _, s := range services {
		if len(s.Spec.Selector) == 0 {
			continue
		}
		svc := protocol.K8sService{Name: clip(s.Metadata.Name, 253), Type: clip(s.Spec.Type, 32), Ports: []int{}}
		for _, p := range s.Spec.Ports {
			if p.Port > 0 && p.Port <= 65535 && len(svc.Ports) < 32 && !containsInt(svc.Ports, p.Port) {
				svc.Ports = append(svc.Ports, p.Port)
			}
		}
		ext := append([]string{}, s.Spec.ExternalIPs...)
		for _, in := range s.Status.LoadBalancer.Ingress {
			ext = append(ext, in.IP)
		}
		// A load-balancer IP that is a node's own IP (k3s servicelb, NodePort
		// style) belongs to the node: giving it to workloads would make the
		// node's IP ambiguous.
		var own []string
		for _, ip := range usableIPs(ext) {
			if !nodeIPs[ip] {
				own = append(own, ip)
			}
		}
		if ext = own; len(ext) > 8 {
			ext = ext[:8]
		}
		svc.ExternalIPs = ext
		for _, w := range all {
			if w.out.Namespace != s.Metadata.Namespace || !matches(s.Spec.Selector, w.labels) {
				continue
			}
			if len(w.out.Services) < 16 {
				w.out.Services = append(w.out.Services, svc)
			}
			key := s.Metadata.Namespace + "/" + s.Metadata.Name
			svcTargets[key] = append(svcTargets[key], w)
		}
	}
	// Ingress host → service → workloads.
	for _, ing := range ingresses {
		ns := ing.Metadata.Namespace
		for _, r := range ing.Spec.Rules {
			host := strings.ToLower(strings.TrimSpace(r.Host))
			if host == "" || strings.Contains(host, "*") || len(host) > 253 {
				continue
			}
			var backends []k8sBackend
			if r.HTTP != nil {
				for _, p := range r.HTTP.Paths {
					backends = append(backends, p.Backend)
				}
			}
			if ing.Spec.DefaultBackend != nil {
				backends = append(backends, *ing.Spec.DefaultBackend)
			}
			for _, b := range backends {
				if b.Service == nil {
					continue
				}
				for _, w := range svcTargets[ns+"/"+b.Service.Name] {
					if !containsString(w.out.Hosts, host) && len(w.out.Hosts) < 32 {
						w.out.Hosts = append(w.out.Hosts, host)
					}
				}
			}
		}
	}
	for _, w := range all {
		out.Workloads = append(out.Workloads, w.out)
	}
	return out
}

func matches(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func containsInt(list []int, n int) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
