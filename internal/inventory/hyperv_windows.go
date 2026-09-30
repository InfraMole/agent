// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/InfraMole/agent/internal/protocol"
)

// HyperV collects the guests of the local Hyper-V host.
type HyperV struct{}

func NewHyperV() (*HyperV, error) { return &HyperV{}, nil }

// Collect runs the fixed read-only script with Windows PowerShell (full
// path: never resolved through PATH).
func (HyperV) Collect(ctx context.Context) (*protocol.Hypervisor, error) {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", hyperVScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "Get-VM") && (strings.Contains(msg, "not recognized") || strings.Contains(msg, "no se reconoce")) {
			return nil, errors.New("hyperv: the Hyper-V PowerShell module is not installed on this host")
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("hyperv: %v: %s", err, msg)
	}
	return parseHyperV(bytes.TrimSpace(stdout.Bytes()))
}
