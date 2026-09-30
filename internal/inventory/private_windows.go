// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package inventory

import "os"

// checkPrivate only checks existence on Windows; restrict the file's ACL as
// documented in docs/AGENT.md (same ACL as agent.json).
func checkPrivate(path string) error {
	_, err := os.Stat(path)
	return err
}
