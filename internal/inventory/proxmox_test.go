// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/InfraMole/agent/internal/config"
)

const token = "inframole@pve!inventory=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakePVE serves /cluster/resources over TLS and returns a CA file for it.
func fakePVE(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv, writeFile(t, "ca.pem", string(ca))
}

func TestCollectFiltersAndAuthenticates(t *testing.T) {
	srv, ca := fakePVE(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/cluster/resources" || r.Header.Get("Authorization") != "PVEAPIToken="+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"node/pve01","type":"node","node":"pve01","status":"online","maxmem":68719476736,"cpu":0.1},
			{"id":"qemu/100","type":"qemu","node":"pve01","name":"APP01","vmid":100,"status":"running","maxmem":8589934592,"diskread":123},
			{"id":"storage/pve01/local","type":"storage","node":"pve01","storage":"local"},
			{"id":"lxc/101","type":"lxc","node":"pve01","name":"redis","vmid":101,"status":"running"},
			{"id":"pool/prod","type":"pool","pool":"prod"}
		]}`))
	})
	p, err := NewProxmox(config.ProxmoxCollector{URL: srv.URL + "/", TokenFile: writeFile(t, "token", token+"\n"), CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "proxmox" || len(inv.Items) != 3 {
		t.Fatalf("got %+v", inv)
	}
	if got := inv.Items[1]; got.Name != "APP01" || got.VMID != 100 || got.MaxMem != 8589934592 {
		t.Fatalf("qemu item: %+v", got)
	}
}

func TestCollectErrorsAndRedirects(t *testing.T) {
	var hits int
	srv, ca := fakePVE(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/elsewhere" {
			t.Error("redirect was followed")
		}
		if hits == 1 {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	p, err := NewProxmox(config.ProxmoxCollector{URL: srv.URL, TokenFile: writeFile(t, "token", token), CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("redirect: %v", err)
	}
	_, err = p.Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "PVEAuditor") || strings.Contains(err.Error(), "0f1e2d3c") {
		t.Fatalf("401 should explain privileges without echoing the token: %v", err)
	}
}

func TestUntrustedCertificateIsRejected(t *testing.T) {
	srv, _ := fakePVE(t, func(w http.ResponseWriter, r *http.Request) {})
	p, err := NewProxmox(config.ProxmoxCollector{URL: srv.URL, TokenFile: writeFile(t, "token", token)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Collect(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected a certificate error, got %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	good := writeFile(t, "token", token)
	cases := map[string]config.ProxmoxCollector{
		"http":        {URL: "http://pve01:8006", TokenFile: good},
		"userinfo":    {URL: "https://root:pw@pve01:8006", TokenFile: good},
		"no token":    {URL: "https://pve01:8006"},
		"bad token":   {URL: "https://pve01:8006", TokenFile: writeFile(t, "bad", "root:password")},
		"missing":     {URL: "https://pve01:8006", TokenFile: filepath.Join(t.TempDir(), "nope")},
		"missing ca":  {URL: "https://pve01:8006", TokenFile: good, CAFile: filepath.Join(t.TempDir(), "nope")},
		"invalid pem": {URL: "https://pve01:8006", TokenFile: good, CAFile: writeFile(t, "ca", "not pem")},
	}
	for name, c := range cases {
		if _, err := NewProxmox(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if runtime.GOOS != "windows" {
		loose := writeFile(t, "loose", token)
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := NewProxmox(config.ProxmoxCollector{URL: "https://pve01:8006", TokenFile: loose}); err == nil ||
			!strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("world-readable token file accepted: %v", err)
		}
	}
}

func TestIntervalClamp(t *testing.T) {
	for in, want := range map[int]int{0: 3600, 10: 300, 900: 900, 999999: 86400} {
		if got := (config.ProxmoxCollector{IntervalSec: in}).Interval().Seconds(); int(got) != want {
			t.Errorf("Interval(%d) = %v, want %d", in, got, want)
		}
	}
}
