// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package inventory

import (
	"fmt"
	"os"
)

// checkPrivate only checks existence on Windows; restrict the file's ACL as
// documented in docs/AGENT.md (same ACL as agent.json).
func checkPrivate(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("proxmox: tokenFile: %w", err)
	}
	return nil
}
