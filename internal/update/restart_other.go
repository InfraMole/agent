// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package update

// EnsureServiceRestart: systemd units have Restart=always, nothing to do.
func EnsureServiceRestart(string) error { return nil }
