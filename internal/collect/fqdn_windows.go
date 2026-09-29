// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package collect

import (
	"strings"

	"golang.org/x/sys/windows"
)

// fqdn uses the DNS fully-qualified computer name (domain-joined hosts).
func fqdn(hostname string) string {
	const computerNameDnsFullyQualified = 3
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(computerNameDnsFullyQualified, &buf[0], &n); err != nil {
		return fqdnFromDNS(hostname)
	}
	name := windows.UTF16ToString(buf[:n])
	if !strings.Contains(name, ".") || strings.EqualFold(name, hostname) {
		return ""
	}
	return truncate(name, 253)
}
