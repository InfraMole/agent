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
	MaxIISSites        = 200
	MaxBindingsPerSite = 20
	MaxSQLDatabases    = 500
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
	// Features lists the optional report sections the server accepts (M16).
	// An agent never sends a section the server did not list.
	Features []string `json:"features,omitempty"`
}

// FeatureWorkloads: the server accepts Report.Workloads (IIS, SQL Server).
const FeatureWorkloads = "workloads"

// FeatureWorkloadsLinux: the server also accepts the Linux workload fields
// (nginx, Apache, PostgreSQL, MySQL — M20).
const FeatureWorkloadsLinux = "workloads-linux"

// FeatureHypervisors: the server accepts Report.Hypervisors (M24).
const FeatureHypervisors = "hypervisors"

// Hypervisor limits enforced by the server.
const (
	MaxHypervisorHosts = 500
	MaxVMIPs           = 16
)

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
	Hypervisors   []Hypervisor `json:"hypervisors,omitempty"`
	Workloads     *Workloads   `json:"workloads,omitempty"`
}

// Hypervisor is one agent-side hypervisor collection (M24): hosts and VMs of
// vCenter / ESXi, Hyper-V (this host; no hosts, VMs without Host) or Xen
// Orchestra. A full snapshot of that platform.
type Hypervisor struct {
	Source      string           `json:"source"` // "vcenter" | "hyperv" | "xenorchestra"
	CollectedAt time.Time        `json:"collectedAt"`
	Hosts       []HypervisorHost `json:"hosts"`
	VMs         []VM             `json:"vms"`
}

type HypervisorHost struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Cluster string `json:"cluster,omitempty"`
	Status  string `json:"status,omitempty"`
	Version string `json:"version,omitempty"`
}

// VM: names, placement, size and guest IPs only.
type VM struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Host     string   `json:"host,omitempty"`
	Status   string   `json:"status,omitempty"`
	CPUs     int      `json:"cpus,omitempty"`
	MemoryMB int      `json:"memoryMb,omitempty"`
	OS       string   `json:"os,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	IPs      []string `json:"ips,omitempty"`
	Template bool     `json:"template,omitempty"`
}

// Workloads (M16 Windows, M20 Linux): what runs on a host, names only. A
// nil slice pointer means "not collected"; a pointer to an empty slice
// means "none".
type Workloads struct {
	CollectedAt       time.Time   `json:"collectedAt"`
	IISSites          *[]WebSite  `json:"iisSites,omitempty"`
	SQLDatabases      *[]Database `json:"sqlDatabases,omitempty"`
	NginxSites        *[]WebSite  `json:"nginxSites,omitempty"`
	ApacheSites       *[]WebSite  `json:"apacheSites,omitempty"`
	PostgresDatabases *[]Database `json:"postgresDatabases,omitempty"`
	MySQLDatabases    *[]Database `json:"mysqlDatabases,omitempty"`
}

// HasLinux: any Linux-only field is set (needs FeatureWorkloadsLinux).
func (w *Workloads) HasLinux() bool {
	return w != nil && (w.NginxSites != nil || w.ApacheSites != nil || w.PostgresDatabases != nil || w.MySQLDatabases != nil)
}

// WebSite: an IIS site, nginx server block or Apache virtual host — name and
// bindings only. Paths, pools, certificates and credentials are never read.
type WebSite struct {
	Name     string       `json:"name"`
	Bindings []WebBinding `json:"bindings"`
}

type WebBinding struct {
	Protocol string `json:"protocol"` // "http" | "https"
	Port     int    `json:"port"`
	Host     string `json:"host,omitempty"` // host header; empty = any
}

// Database: a user database name of a local engine instance.
type Database struct {
	// SQL Server instance ("MSSQLSERVER" = default), PostgreSQL port, MySQL "default".
	Instance string `json:"instance"`
	Name     string `json:"name"`
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
