// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"strings"
	"testing"
)

// Output of hyperVScript (ConvertTo-Json -InputObject @(...) always yields an array).
func TestParseHyperV(t *testing.T) {
	out := []byte(`[{"id":"3f2a6c1e-8a55-4c55-9b1f-2d9a2b0f7c11","name":"DC01","state":"Running","cpus":2,"memoryMb":4096,"ips":["10.0.0.10","fe80::5"]},
	                {"id":"a1b2c3d4-0000-0000-0000-000000000000","name":"Lab","state":"Off","cpus":1,"memoryMb":1024,"ips":[]}]`)
	inv, err := parseHyperV(out)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "hyperv" || len(inv.Hosts) != 0 || len(inv.VMs) != 2 {
		t.Fatalf("%+v", inv)
	}
	dc := inv.VMs[0]
	if dc.Name != "DC01" || dc.Host != "" || dc.CPUs != 2 || dc.MemoryMB != 4096 || strings.Join(dc.IPs, ",") != "10.0.0.10" {
		t.Fatalf("%+v", dc)
	}
	if empty, err := parseHyperV([]byte(`[]`)); err != nil || len(empty.VMs) != 0 {
		t.Fatalf("empty: %v %+v", err, empty)
	}
	if _, err := parseHyperV([]byte(`Get-VM : error`)); err == nil {
		t.Fatal("accepted non-JSON output")
	}
}

func TestHyperVScriptIsFixed(t *testing.T) {
	// Read-only cmdlets only; nothing that changes a VM.
	for _, verb := range []string{"Start-", "Stop-", "Set-", "Remove-", "New-", "Invoke-", "Restart-"} {
		if strings.Contains(hyperVScript, verb) {
			t.Fatalf("script contains %s", verb)
		}
	}
}
