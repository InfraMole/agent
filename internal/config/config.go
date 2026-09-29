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
}

type Collectors struct {
	Proxmox *ProxmoxCollector `json:"proxmox,omitempty"`
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
