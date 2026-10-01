// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/report.golden.json")

// GoldenReport is a deterministic report exercising every field. The web
// test suite validates testdata/report.golden.json against the zod schema.
func GoldenReport() Report {
	t0 := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	boot := time.Date(2026, 9, 1, 6, 30, 0, 0, time.UTC)
	return Report{
		SchemaVersion: SchemaVersion,
		AgentVersion:  "0.1.0",
		CollectedAt:   t0.Add(5 * time.Minute),
		WindowStart:   t0,
		Host: Host{
			Hostname: "APP01", FQDN: "app01.corp.local", OS: "windows",
			OSName: "Microsoft Windows Server 2022 Standard", OSVersion: "10.0.20348",
			KernelVersion: "10.0.20348", Arch: "amd64", BootTime: &boot,
		},
		Interfaces: []Interface{{Name: "Ethernet0", MAC: "00:15:5d:01:02:03", Addresses: []string{"10.0.0.23/24", "fe80::1/64"}}},
		Services:   []Service{{Name: "W3SVC", DisplayName: "World Wide Web Publishing Service", State: "running", StartType: "auto"}},
		Listeners:  []Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 443, Process: &ProcessRef{Name: "System", PID: 4}}},
		Connections: []Connection{
			{Proto: "tcp", Direction: "outbound", RemoteAddress: "10.0.0.40", RemotePort: 1433,
				Process: &ProcessRef{Name: "w3wp.exe", Path: `C:\Windows\System32\inetsrv\w3wp.exe`},
				Count:   10, FirstSeen: t0, LastSeen: t0.Add(270 * time.Second)},
			{Proto: "tcp", Direction: "inbound", LocalPort: 443, RemoteAddress: "10.0.1.5",
				Count: 3, FirstSeen: t0, LastSeen: t0.Add(60 * time.Second)},
		},
		Truncated: true,
		Inventory: &Inventory{
			Source: "proxmox", CollectedAt: t0.Add(5 * time.Minute),
			Items: []InventoryItem{
				{ID: "node/pve01", Type: "node", Node: "pve01", Status: "online", MaxMem: 68719476736},
				{ID: "qemu/100", Type: "qemu", Node: "pve01", Name: "APP01", VMID: 100, Status: "running", MaxMem: 8589934592},
				{ID: "qemu/9000", Type: "qemu", Node: "pve01", Name: "tpl-debian", VMID: 9000, Status: "stopped", Template: 1},
			},
		},
		Kubernetes: &Kubernetes{
			Cluster: "prod", CollectedAt: t0.Add(5 * time.Minute),
			Nodes: []K8sNode{{Name: "k8s-node1", IPs: []string{"10.0.1.11"}, Version: "v1.31.2", OS: "Ubuntu 24.04.1 LTS"}},
			Workloads: []K8sWorkload{{
				Namespace: "shop", Name: "web", Kind: "Deployment", Images: []string{"ghcr.io/acme/shop:1.4.2"},
				Replicas: intPtr(2), Ready: intPtr(2), Nodes: []string{"k8s-node1"},
				Services: []K8sService{{Name: "web", Type: "LoadBalancer", Ports: []int{80}, ExternalIPs: []string{"203.0.113.40"}}},
				Hosts:    []string{"shop.example.com"},
			}},
		},
		Hypervisors: []Hypervisor{
			{
				Source: "vcenter", CollectedAt: t0.Add(5 * time.Minute),
				Hosts: []HypervisorHost{{ID: "host-21", Name: "esx01.corp.local", Cluster: "Prod", Status: "connected", Version: "VMware ESXi 8.0.3"}},
				VMs: []VM{
					{ID: "vm-42", Name: "APP01", Host: "host-21", Status: "poweredOn", CPUs: 4, MemoryMB: 8192,
						OS: "Microsoft Windows Server 2022 (64-bit)", Hostname: "app01.corp.local", IPs: []string{"10.0.0.23", "fe80::1"}},
					{ID: "vm-7", Name: "tpl-win2022", Host: "host-21", Status: "poweredOff", Template: true},
				},
			},
			{
				Source: "hyperv", CollectedAt: t0.Add(5 * time.Minute), Hosts: []HypervisorHost{},
				VMs: []VM{{ID: "3f2a6c1e-8a55-4c55-9b1f-2d9a2b0f7c11", Name: "DC01", Status: "Running", CPUs: 2, MemoryMB: 4096, IPs: []string{"10.0.0.10"}}},
			},
		},
		Workloads: &Workloads{
			CollectedAt: t0.Add(5 * time.Minute),
			IISSites: &[]WebSite{
				{Name: "Portal", Bindings: []WebBinding{{Protocol: "https", Port: 443, Host: "portal.corp.local"}, {Protocol: "http", Port: 80}}},
				{Name: "Default Web Site", Bindings: []WebBinding{}},
			},
			SQLDatabases: &[]Database{{Instance: "MSSQLSERVER", Name: "Customers"}, {Instance: "REPORTING", Name: "Sales"}},
			NginxSites: &[]WebSite{
				{Name: "shop.example.com", Bindings: []WebBinding{{Protocol: "https", Port: 443, Host: "shop.example.com"}},
					Upstreams: []Upstream{{Host: "127.0.0.1", Port: 3000}}},
			},
			ApacheSites: &[]WebSite{},
			HAProxySites: &[]WebSite{{Name: "web", Bindings: []WebBinding{{Protocol: "https", Port: 443}},
				Upstreams: []Upstream{{Host: "10.0.0.31", Port: 8080}}}},
			PostgresDatabases: &[]Database{{Instance: "5432", Name: "orders"}},
			MySQLDatabases:    &[]Database{{Instance: "default", Name: "wordpress"}},
			Containers: &[]Container{
				{Name: "shop-db-1", Image: "postgres:16-alpine", State: "running", Ports: []ContainerPort{{Port: 5432, TargetPort: 5432, Protocol: "tcp"}},
					Project: "shop", Service: "db"},
				{Name: "shop-web-1", Image: "ghcr.io/acme/shop:1.4.2", State: "running", Ports: []ContainerPort{},
					Project: "shop", Service: "web", DependsOn: []string{"db"}, Hosts: []string{"shop.example.com"}},
			},
		},
	}
}

func TestGoldenReport(t *testing.T) {
	got, err := json.MarshalIndent(GoldenReport(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "report.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run `go test ./internal/protocol -update`): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Fatalf("golden mismatch; if the protocol changed on purpose, update the zod schema first, then run `go test ./internal/protocol -update`\n%s", got)
	}
}

func TestClampConfig(t *testing.T) {
	cases := []struct{ in, want Config }{
		{Config{5, 30}, Config{60, 30}},
		{Config{300, 30}, Config{300, 30}},
		{Config{99999, 30}, Config{3600, 30}},
		{Config{120, 1}, Config{120, 30}},
	}
	for _, c := range cases {
		if got := ClampConfig(c.in); got != c.want {
			t.Errorf("ClampConfig(%+v) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func intPtr(n int) *int { return &n }
