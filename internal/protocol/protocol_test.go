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
