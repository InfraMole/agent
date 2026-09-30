// SPDX-License-Identifier: AGPL-3.0-only
package inventory

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

// hyperVScript lists the local Hyper-V guests with the Hyper-V PowerShell
// module (read-only cmdlets; runs as the agent's service identity). Fixed
// text: nothing from the server or the config file is interpolated.
const hyperVScript = `$ErrorActionPreference = 'Stop'
$vms = @(Get-VM | ForEach-Object {
  [pscustomobject]@{
    id       = $_.VMId.Guid
    name     = $_.Name
    state    = [string]$_.State
    cpus     = $_.ProcessorCount
    memoryMb = [int64]($_.MemoryStartup / 1MB)
    ips      = @($_.NetworkAdapters | ForEach-Object { $_.IPAddresses })
  }
})
ConvertTo-Json -InputObject $vms -Depth 3 -Compress`

type hyperVVM struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	State    string   `json:"state"`
	CPUs     int      `json:"cpus"`
	MemoryMB int64    `json:"memoryMb"`
	IPs      []string `json:"ips"`
}

// parseHyperV turns the script's JSON into the protocol shape. The host is
// the agent's own machine: no hosts, VMs without Host (the server attaches
// them to the agent's host).
func parseHyperV(out []byte) (*protocol.Hypervisor, error) {
	var vms []hyperVVM
	if err := json.Unmarshal(out, &vms); err != nil {
		return nil, fmt.Errorf("hyperv: unexpected output: %w", err)
	}
	inv := &protocol.Hypervisor{Source: "hyperv", CollectedAt: time.Now().UTC(), Hosts: []protocol.HypervisorHost{}, VMs: []protocol.VM{}}
	for _, v := range vms {
		if v.ID == "" || v.Name == "" || len(inv.VMs) >= protocol.MaxInventoryItems {
			continue
		}
		inv.VMs = append(inv.VMs, protocol.VM{
			ID: clip(v.ID, 128), Name: clip(v.Name, 253), Status: clip(v.State, 32),
			CPUs: max(v.CPUs, 0), MemoryMB: int(max(v.MemoryMB, 0)), IPs: usableIPs(v.IPs),
		})
	}
	return inv, nil
}
