// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// MaxDNSServers: the server accepts at most this many resolvers per host.
const MaxDNSServers = 8

// usableResolvers keeps unique, routable resolver addresses in order (M39):
// loopback (local stubs), link-local, unspecified, multicast and the
// deprecated site-local fec0::/10 defaults Windows lists are dropped —
// they never point at another machine of the inventory.
func usableResolvers(candidates []string) []string {
	siteLocal := netip.MustParsePrefix("fec0::/10")
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range candidates {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() || siteLocal.Contains(addr) {
			continue
		}
		s := addr.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == MaxDNSServers {
			break
		}
	}
	return out
}

// parseResolvConf returns the `nameserver` addresses of a resolv.conf, in
// order (comments and other options ignored).
func parseResolvConf(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}
