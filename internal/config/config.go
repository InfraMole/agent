// SPDX-License-Identifier: AGPL-3.0-only
// Package config stores the agent's local configuration, including its
// secret, in a file readable only by privileged accounts.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type File struct {
	Server            string `json:"server"`
	AgentID           string `json:"agentId"`
	AgentSecret       string `json:"agentSecret"`
	InsecureDev       bool   `json:"insecureDev,omitempty"`
	ReportIntervalSec int    `json:"reportIntervalSec"`
	SampleIntervalSec int    `json:"sampleIntervalSec"`
	// Collectors are set only by editing this file locally; the server can
	// never enable or change them (ADR-018 C).
	Collectors *Collectors `json:"collectors,omitempty"`
	// AutoUpdate (M22, ADR-033): install newer signed releases on its own.
	// Local only — the server cannot turn it on or choose where updates come from.
	AutoUpdate bool `json:"autoUpdate,omitempty"`
	// UpdateBaseURL: a local mirror of the release files (default: GitHub releases).
	UpdateBaseURL string `json:"updateBaseUrl,omitempty"`
}

type Collectors struct {
	Proxmox      *ProxmoxCollector      `json:"proxmox,omitempty"`
	VCenter      *VCenterCollector      `json:"vcenter,omitempty"`
	XenOrchestra *XenOrchestraCollector `json:"xenOrchestra,omitempty"`
	HyperV       *HyperVCollector       `json:"hyperv,omitempty"`
	Kubernetes   *KubernetesCollector   `json:"kubernetes,omitempty"`
	Workloads    *WorkloadsCollector    `json:"workloads,omitempty"`
}

// VCenterCollector (M24) reads hosts and VMs from vCenter or a standalone
// ESXi host with a read-only user. The password lives in its own file.
type VCenterCollector struct {
	URL                string `json:"url"`          // https://vcenter.corp.local
	Username           string `json:"username"`     // e.g. inframole@vsphere.local (Read-only role)
	PasswordFile       string `json:"passwordFile"` // the password, nothing else
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	IntervalSec        int    `json:"intervalSec,omitempty"` // default 3600, min 300
}

// XenOrchestraCollector (M24) reads XCP-ng hosts and VMs from Xen
// Orchestra's REST API with an authentication token of a read-only user.
type XenOrchestraCollector struct {
	URL                string `json:"url"`       // https://xo.corp.local
	TokenFile          string `json:"tokenFile"` // the token, nothing else
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	IntervalSec        int    `json:"intervalSec,omitempty"` // default 3600, min 300
}

// HyperVCollector (M24, Windows): the VMs of the local Hyper-V host. Present
// (even empty: {}) = enabled.
type HyperVCollector struct {
	IntervalSec int `json:"intervalSec,omitempty"` // default 3600, min 300
}

// KubernetesCollector (M25) reads nodes and workloads of one cluster with a
// get/list-only service account token, from outside (url + tokenFile) or
// from a pod in the cluster (inCluster: the mounted service account).
type KubernetesCollector struct {
	Cluster            string `json:"cluster"`             // name shown in InfraMole
	URL                string `json:"url,omitempty"`       // https://k8s-api.corp.local:6443
	TokenFile          string `json:"tokenFile,omitempty"` // the service account token
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	InCluster          bool   `json:"inCluster,omitempty"`
	// System namespaces (kube-system, kube-public, kube-node-lease) are
	// skipped unless this is set.
	IncludeSystemNamespaces bool `json:"includeSystemNamespaces,omitempty"`
	IntervalSec             int  `json:"intervalSec,omitempty"` // default 3600, min 300
}

// ClampInterval clamps a collector cadence to [5 min, 1 day], default 1 h.
func ClampInterval(sec int) time.Duration {
	return ProxmoxCollector{IntervalSec: sec}.Interval()
}

// WorkloadsCollector (M16 Windows, M20 Linux). Web sites (IIS, nginx,
// Apache — read from their configuration files) are reported by default.
// Database names are opt-in: the agent connects to the local instances with
// its own OS identity (Windows integrated auth, PostgreSQL peer, MySQL
// unix_socket / auth_socket) — no credentials are ever stored.
type WorkloadsCollector struct {
	WebServers  *bool `json:"webServers,omitempty"`  // default true (IIS, nginx, Apache)
	IIS         *bool `json:"iis,omitempty"`         // M16 name; false also turns web sites off on Windows
	SQLServer   bool  `json:"sqlServer,omitempty"`   // default false (Windows)
	PostgreSQL  bool  `json:"postgresql,omitempty"`  // default false (Linux)
	MySQL       bool  `json:"mysql,omitempty"`       // default false (Linux: MySQL and MariaDB)
	Docker      *bool `json:"docker,omitempty"`      // default true (Linux: container list from the local socket)
	IntervalSec int   `json:"intervalSec,omitempty"` // default 3600, min 300
}

// WebServersEnabled: on unless explicitly turned off ("webServers" or, on
// configurations written for M16, "iis").
func (c *Collectors) WebServersEnabled() bool {
	if c == nil || c.Workloads == nil {
		return true
	}
	w := c.Workloads
	return (w.WebServers == nil || *w.WebServers) && (w.IIS == nil || *w.IIS)
}

// IISEnabled is kept for configurations and code written for M16.
func (c *Collectors) IISEnabled() bool { return c.WebServersEnabled() }

// PostgreSQLEnabled / MySQLEnabled: off unless explicitly turned on.
func (c *Collectors) PostgreSQLEnabled() bool {
	return c != nil && c.Workloads != nil && c.Workloads.PostgreSQL
}

func (c *Collectors) MySQLEnabled() bool {
	return c != nil && c.Workloads != nil && c.Workloads.MySQL
}

// DockerEnabled: on unless explicitly turned off (M25).
func (c *Collectors) DockerEnabled() bool {
	return c == nil || c.Workloads == nil || c.Workloads.Docker == nil || *c.Workloads.Docker
}

// SQLServerEnabled: off unless explicitly turned on.
func (c *Collectors) SQLServerEnabled() bool {
	return c != nil && c.Workloads != nil && c.Workloads.SQLServer
}

// WorkloadsInterval clamps the cadence to [5 min, 1 day], default 1 h.
func (c *Collectors) WorkloadsInterval() time.Duration {
	if c == nil || c.Workloads == nil {
		return time.Hour
	}
	return ProxmoxCollector{IntervalSec: c.Workloads.IntervalSec}.Interval()
}

// ProxmoxCollector reads /cluster/resources with a read-only API token
// (PVEAuditor). The token lives in its own file, never in agent.json.
type ProxmoxCollector struct {
	URL                string `json:"url"`       // https://pve01.lan:8006
	TokenFile          string `json:"tokenFile"` // contains USER@REALM!TOKENID=SECRET
	CAFile             string `json:"caFile,omitempty"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	IntervalSec        int    `json:"intervalSec,omitempty"` // default 3600, min 300
}

// Interval clamps the collection cadence to [5 min, 1 day], default 1 h.
func (p ProxmoxCollector) Interval() time.Duration {
	sec := p.IntervalSec
	switch {
	case sec <= 0:
		sec = 3600
	case sec < 300:
		sec = 300
	case sec > 86400:
		sec = 86400
	}
	return time.Duration(sec) * time.Second
}

// DefaultPath: %ProgramData%\InfraMole\agent.json or /etc/inframole/agent.json.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "InfraMole", "agent.json")
	}
	return "/etc/inframole/agent.json"
}

var ErrNotEnrolled = errors.New("agent is not enrolled (run `inframole-agent enroll` or `install`)")

func Load(path string) (*File, error) {
	f, err := Read(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	if f.Server == "" || f.AgentID == "" || f.AgentSecret == "" {
		return nil, ErrNotEnrolled
	}
	return f, nil
}

// Read parses the file without requiring enrollment (dry-run --inventory).
func Read(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

// Save writes atomically and restricts access (0600 / SYSTEM+Administrators+owner).
func Save(path string, f *File) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := restrict(dir, true); err != nil {
		return fmt.Errorf("restrict %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := restrict(tmp, false); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("restrict %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}

// Remove deletes the config file (used by uninstall).
func Remove(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
