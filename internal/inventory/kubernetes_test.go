// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/InfraMole/agent/internal/config"
)

const k8sToken = "eyJhbGciOiJSUzI1NiJ9.test-token"

// Minimal API server: list endpoints shaped like the real API (objects carry
// fields the agent must never send: env values, annotations, labels).
func fakeK8s(t *testing.T) *httptest.Server {
	t.Helper()
	items := map[string]string{
		"/api/v1/nodes": `[{"metadata":{"name":"node1","labels":{"kubernetes.io/hostname":"node1"}},
			"status":{"addresses":[{"type":"InternalIP","address":"10.0.1.11"},{"type":"Hostname","address":"node1"}],
			"nodeInfo":{"kubeletVersion":"v1.31.2","osImage":"Ubuntu 24.04.1 LTS"}}}]`,
		"/api/v1/pods": `[
			{"metadata":{"namespace":"shop","name":"web-5d9c-abcde","labels":{"app":"web"},"ownerReferences":[{"kind":"ReplicaSet","name":"web-5d9c"}]},
			 "spec":{"nodeName":"node1","containers":[{"image":"x","env":[{"name":"DB_PASSWORD","value":"SECRET-ENV"}]}]},"status":{"phase":"Running"}},
			{"metadata":{"namespace":"shop","name":"db-0","ownerReferences":[{"kind":"StatefulSet","name":"db"}]},"spec":{"nodeName":"node1"},"status":{"phase":"Running"}},
			{"metadata":{"namespace":"shop","name":"old-1","ownerReferences":[{"kind":"ReplicaSet","name":"web-5d9c"}]},"spec":{"nodeName":"node9"},"status":{"phase":"Succeeded"}}]`,
		"/apis/apps/v1/replicasets": `[{"metadata":{"namespace":"shop","name":"web-5d9c","ownerReferences":[{"kind":"Deployment","name":"web"}]}}]`,
		"/apis/apps/v1/deployments": `[{"metadata":{"namespace":"shop","name":"web","annotations":{"secret":"SECRET-ANN"}},
			"spec":{"replicas":2,"template":{"metadata":{"labels":{"app":"web","tier":"front"}},
			"spec":{"containers":[{"image":"ghcr.io/acme/shop:1.4.2","env":[{"name":"API_KEY","value":"SECRET-ENV"}]}]}}},
			"status":{"readyReplicas":2}}]`,
		"/apis/apps/v1/statefulsets": `[{"metadata":{"namespace":"shop","name":"db"},
			"spec":{"replicas":1,"template":{"metadata":{"labels":{"app":"db"}},"spec":{"containers":[{"image":"postgres:16"}]}}},"status":{"readyReplicas":1}}]`,
		"/apis/apps/v1/daemonsets": `[]`,
		"/api/v1/services": `[
			{"metadata":{"namespace":"shop","name":"web"},"spec":{"type":"LoadBalancer","selector":{"app":"web"},"ports":[{"port":80}]},
			 "status":{"loadBalancer":{"ingress":[{"ip":"203.0.113.40"}]}}},
			{"metadata":{"namespace":"shop","name":"db"},"spec":{"type":"ClusterIP","selector":{"app":"db"},"ports":[{"port":5432}]}},
			{"metadata":{"namespace":"default","name":"kubernetes"},"spec":{"type":"ClusterIP","ports":[{"port":443}]}}]`,
		"/apis/networking.k8s.io/v1/ingresses": `[{"metadata":{"namespace":"shop","name":"web"},
			"spec":{"rules":[{"host":"shop.example.com","http":{"paths":[{"backend":{"service":{"name":"web","port":{"number":80}}}}]}}]}}]`,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+k8sToken || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := items[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"kind":"List","metadata":{},"items":` + body + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestKubernetesCollect(t *testing.T) {
	srv := fakeK8s(t)
	k, err := NewKubernetes(config.KubernetesCollector{Cluster: "prod", URL: srv.URL, TokenFile: secretFile(t, k8sToken), InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := k.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(inv)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "tier") {
		t.Fatalf("leaked: %s", raw)
	}
	if len(inv.Nodes) != 1 || inv.Nodes[0].IPs[0] != "10.0.1.11" || inv.Nodes[0].Version != "v1.31.2" {
		t.Fatalf("nodes %+v", inv.Nodes)
	}
	byName := map[string]int{}
	for i, w := range inv.Workloads {
		byName[w.Name] = i
	}
	web := inv.Workloads[byName["web"]]
	if web.Kind != "Deployment" || strings.Join(web.Nodes, ",") != "node1" || *web.Ready != 2 ||
		len(web.Services) != 1 || web.Services[0].ExternalIPs[0] != "203.0.113.40" || strings.Join(web.Hosts, ",") != "shop.example.com" {
		t.Fatalf("web %+v", web)
	}
	db := inv.Workloads[byName["db"]]
	if db.Kind != "StatefulSet" || db.Images[0] != "postgres:16" || db.Services[0].Ports[0] != 5432 {
		t.Fatalf("db %+v", db)
	}
}

func TestKubernetesRejectedToken(t *testing.T) {
	srv := fakeK8s(t)
	k, err := NewKubernetes(config.KubernetesCollector{Cluster: "prod", URL: srv.URL, TokenFile: secretFile(t, "wrong"), InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewKubernetes(config.KubernetesCollector{URL: srv.URL, TokenFile: secretFile(t, "x")}); err == nil {
		t.Fatal("accepted a collector without a cluster name")
	}
}
