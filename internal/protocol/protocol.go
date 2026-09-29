// SPDX-License-Identifier: AGPL-3.0-only
// Package protocol mirrors the agent wire protocol v1.
//
// The source of truth is the zod schema in
// apps/web/src/server/modules/agents/protocol.ts (exported as JSON Schema to
// agent/contract/report.v1.schema.json). The golden file in testdata is
// validated against that schema by a web unit test, so the two sides cannot
// drift silently. Never add fields here that the server does not accept:
// the server rejects unknown fields (data minimisation).
package protocol

import "time"

const SchemaVersion = 1

// Limits enforced by the server; the agent truncates before sending.
const (
	MaxInterfaces      = 64
	MaxAddresses       = 32
	MaxServices        = 1000
	MaxListeners       = 500
	MaxConnections     = 2000
	MaxInventoryItems  = 2000
	MaxProcessPathLen  = 1024
	MaxShortStringLen  = 256
	MinReportInterval  = 60
	MaxReportInterval  = 3600
	DefaultReportEvery = 300
	DefaultSampleEvery = 30
)

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollmentToken"`
	MachineID       string `json:"machineId"`
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	OSVersion       string `json:"osVersion"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agentVersion"`
}

type Config struct {
	ReportIntervalSec int `json:"reportIntervalSec"`
	SampleIntervalSec int `json:"sampleIntervalSec"`
}

type EnrollResponse struct {
	AgentID     string `json:"agentId"`
	AgentSecret string `json:"agentSecret"`
	Config      Config `json:"config"`
}

type ReportResponse struct {
	Config Config `json:"config"`
}

type Report struct {
	SchemaVersion int          `json:"schemaVersion"`
	AgentVersion  string       `json:"agentVersion"`
	CollectedAt   time.Time    `json:"collectedAt"`
	WindowStart   time.Time    `json:"windowStart"`
	Host          Host         `json:"host"`
	Interfaces    []Interface  `json:"interfaces"`
	Services      []Service    `json:"services"`
	Listeners     []Listener   `json:"listeners"`
	Connections   []Connection `json:"connections"`
	Truncated     bool         `json:"truncated,omitempty"`
	Inventory     *Inventory   `json:"inventory,omitempty"`
}

// Inventory is the optional output of an agent-side collector (ADR-018 C),
// configured only in the local config file. Only the fields the server's
// importer uses are sent.
type Inventory struct {
	Source      string          `json:"source"` // "proxmox"
	CollectedAt time.Time       `json:"collectedAt"`
	Items       []InventoryItem `json:"items"`
}

// InventoryItem mirrors a Proxmox /cluster/resources entry (node, qemu, lxc).
type InventoryItem struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"` // "node" | "qemu" | "lxc"
	Node     string  `json:"node,omitempty"`
	Name     string  `json:"name,omitempty"`
	VMID     int     `json:"vmid,omitempty"`
	Status   string  `json:"status,omitempty"`
	MaxMem   float64 `json:"maxmem,omitempty"`
	Template int     `json:"template,omitempty"`
}

type Host struct {
	Hostname      string     `json:"hostname"`
	FQDN          string     `json:"fqdn,omitempty"`
	OS            string     `json:"os"` // "windows" | "linux"
	OSName        string     `json:"osName"`
	OSVersion     string     `json:"osVersion"`
	KernelVersion string     `json:"kernelVersion,omitempty"`
	Arch          string     `json:"arch"`
	BootTime      *time.Time `json:"bootTime,omitempty"`
}

type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses"` // CIDR, e.g. "10.0.0.23/24"
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	State       string `json:"state"`
	StartType   string `json:"startType,omitempty"`
}

// ProcessRef deliberately has no command line, arguments or environment.
type ProcessRef struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	PID  int32  `json:"pid,omitempty"`
}

type Listener struct {
	Proto   string      `json:"proto"` // "tcp" | "tcp6"
	Address string      `json:"address"`
	Port    uint32      `json:"port"`
	Process *ProcessRef `json:"process,omitempty"`
}

type Connection struct {
	Proto         string      `json:"proto"`
	Direction     string      `json:"direction"` // "inbound" | "outbound"
	LocalPort     uint32      `json:"localPort"` // listening port for inbound, 0 for outbound
	RemoteAddress string      `json:"remoteAddress"`
	RemotePort    uint32      `json:"remotePort"` // 0 for inbound (ephemeral)
	Process       *ProcessRef `json:"process,omitempty"`
	Count         int         `json:"count"`
	FirstSeen     time.Time   `json:"firstSeen"`
	LastSeen      time.Time   `json:"lastSeen"`
}

// ClampConfig applies the same bounds as the server; server-provided config
// is never trusted blindly (docs/AGENT.md §6).
func ClampConfig(c Config) Config {
	if c.ReportIntervalSec < MinReportInterval {
		c.ReportIntervalSec = MinReportInterval
	}
	if c.ReportIntervalSec > MaxReportInterval {
		c.ReportIntervalSec = MaxReportInterval
	}
	if c.SampleIntervalSec < 5 || c.SampleIntervalSec > c.ReportIntervalSec {
		c.SampleIntervalSec = DefaultSampleEvery
	}
	return c
}
