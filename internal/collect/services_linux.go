// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

package collect

import (
	"context"
	"os/exec"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

// Services lists running systemd services. It executes `systemctl` with a
// FIXED argument list (never user or server input). Hosts without systemd
// return an empty list.
func Services(ctx context.Context) ([]protocol.Service, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return []protocol.Service{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path,
		"list-units", "--type=service", "--state=running", "--no-legend", "--plain", "--no-pager",
	).Output()
	if err != nil {
		return nil, err
	}
	return parseSystemctl(string(out)), nil
}
