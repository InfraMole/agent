// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"net/netip"
	"sort"

	"github.com/InfraMole/agent/internal/protocol"
)

// clientRow: one row of the database clients query (M42) — database, the
// client's address as the engine saw it, the server port and a count.
type clientRow struct {
	database string
	address  string
	port     int
	sessions int
}

// toClients keeps remote clients only: local transports ("<local machine>"),
// loopback, link-local and unparseable addresses are dropped. Rows that
// become identical (an IPv4-mapped address) are added up.
func toClients(engine, instance string, rows []clientRow) []protocol.DatabaseClient {
	type key struct {
		db, addr string
		port     int
	}
	sums := map[key]int{}
	for _, r := range rows {
		addr, err := netip.ParseAddr(r.address)
		if err != nil || r.database == "" || r.port < 1 || r.port > 65535 || r.sessions < 1 {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		sums[key{clip(r.database, 128), addr.String(), r.port}] += r.sessions
	}
	out := make([]protocol.DatabaseClient, 0, len(sums))
	for k, n := range sums {
		out = append(out, protocol.DatabaseClient{
			Engine: engine, Instance: clip(instance, 128), Database: k.db,
			Address: k.addr, Port: k.port, Sessions: min(n, protocol.MaxSessions),
		})
	}
	sortClients(out)
	return out
}

func sortClients(list []protocol.DatabaseClient) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Engine != b.Engine {
			return a.Engine < b.Engine
		}
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		if a.Database != b.Database {
			return a.Database < b.Database
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Port < b.Port
	})
}
