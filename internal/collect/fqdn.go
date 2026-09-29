// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"net"
	"strings"
)

// fqdnFromDNS resolves the canonical name of the host, if it has a domain.
func fqdnFromDNS(hostname string) string {
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return ""
	}
	cname = strings.TrimSuffix(cname, ".")
	if !strings.Contains(cname, ".") || strings.EqualFold(cname, hostname) {
		return ""
	}
	return truncate(cname, 253)
}
