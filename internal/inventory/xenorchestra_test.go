// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/InfraMole/agent/internal/config"
)

const xoToken = "KQxQdm2vMiv7jBIK0hgkmgxKzemd8wSJ7ugFGKFkTbs"

// Responses shaped like the documented REST API (collections with ?fields=).
func fakeXO(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("authenticationToken"); err != nil || c.Value != xoToken || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(r.URL.RawQuery, "fields=") {
			t.Errorf("collection without fields: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/v0/pools":
			_, _ = w.Write([]byte(`[{"id":"pool-1","name_label":"Prod pool","href":"/rest/v0/pools/pool-1"}]`))
		case "/rest/v0/hosts":
			_, _ = w.Write([]byte(`[{"id":"host-a","name_label":"xcp01","power_state":"Running","version":"8.3.0","productBrand":"XCP-ng","$pool":"pool-1","href":"/rest/v0/hosts/host-a"}]`))
		case "/rest/v0/vms":
			_, _ = w.Write([]byte(`[
			  {"id":"770aa52a","name_label":"Debian 12 web frontend","power_state":"Running","$container":"host-a",
			   "CPUs":{"max":4,"number":2},"memory":{"size":4294967296},
			   "addresses":{"0/ipv6/0":"fe80::1","0/ipv4/0":"192.168.1.55"},"os_version":{"name":"Debian GNU/Linux 12"},
			   "href":"/rest/v0/vms/770aa52a"},
			  {"id":"0fc14abc","name_label":"FreeNAS","power_state":"Halted","$container":"pool-1",
			   "CPUs":{"number":1},"memory":{"size":2147483648},"addresses":{},"os_version":null,"href":"/rest/v0/vms/0fc14abc"}
			]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestXenOrchestraCollect(t *testing.T) {
	srv := fakeXO(t)
	x, err := NewXenOrchestra(config.XenOrchestraCollector{URL: srv.URL, TokenFile: secretFile(t, xoToken), InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := x.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Hosts) != 1 || inv.Hosts[0].Cluster != "Prod pool" || inv.Hosts[0].Version != "XCP-ng 8.3.0" {
		t.Fatalf("hosts %+v", inv.Hosts)
	}
	web, nas := inv.VMs[0], inv.VMs[1]
	if web.Host != "host-a" || web.CPUs != 2 || web.MemoryMB != 4096 || web.OS != "Debian GNU/Linux 12" ||
		len(web.IPs) != 1 || web.IPs[0] != "192.168.1.55" {
		t.Fatalf("web %+v", web)
	}
	if nas.Host != "" || nas.Status != "Halted" {
		t.Fatalf("halted VM must not be placed on the pool: %+v", nas)
	}
}

func TestXenOrchestraBadToken(t *testing.T) {
	srv := fakeXO(t)
	x, err := NewXenOrchestra(config.XenOrchestraCollector{URL: srv.URL, TokenFile: secretFile(t, "wrong-token"), InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("err = %v", err)
	}
}
