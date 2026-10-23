// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

// Socket is one row of the OS TCP table (already resolved to plain values).
type Socket struct {
	LocalIP    string
	LocalPort  uint32
	RemoteIP   string
	RemotePort uint32
	Status     string // "LISTEN", "ESTABLISHED", ...
	PID        int32
}

// ProcessResolver maps a PID to a process reference (name + path, never args).
type ProcessResolver func(pid int32) *protocol.ProcessRef

// Listeners returns the distinct listening sockets.
func Listeners(sockets []Socket, resolve ProcessResolver) []protocol.Listener {
	seen := map[string]bool{}
	out := []protocol.Listener{}
	for _, s := range sockets {
		if s.Status != "LISTEN" {
			continue
		}
		key := s.LocalIP + "|" + itoa(s.LocalPort)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, protocol.Listener{
			Proto:   proto(s.LocalIP),
			Address: s.LocalIP,
			Port:    s.LocalPort,
			Process: resolve(s.PID),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// ListeningPorts is the set of local ports with a listener (any address).
func ListeningPorts(sockets []Socket) map[uint32]bool {
	ports := map[uint32]bool{}
	for _, s := range sockets {
		if s.Status == "LISTEN" {
			ports[s.LocalPort] = true
		}
	}
	return ports
}

type connKey struct {
	direction string
	remote    string
	port      uint32 // local port (inbound) or remote port (outbound)
	process   string
}

// Aggregator accumulates established connections across samples so that a
// report every few minutes still reflects connections seen every ~30 s
// (docs/AGENT.md §4). Safe for concurrent use.
type Aggregator struct {
	mu          sync.Mutex
	entries     map[connKey]*protocol.Connection
	windowStart time.Time
	truncated   bool
	max         int
}

func NewAggregator(now time.Time) *Aggregator {
	return &Aggregator{entries: map[connKey]*protocol.Connection{}, windowStart: now, max: protocol.MaxConnections}
}

// Add records one sample. Loopback / link-local / unspecified peers are
// dropped; direction is inbound when the local port has a listener.
func (a *Aggregator) Add(sockets []Socket, resolve ProcessResolver, now time.Time) {
	listening := ListeningPorts(sockets)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range sockets {
		if s.Status != "ESTABLISHED" || !isRemotePeer(s.RemoteIP) {
			continue
		}
		c := protocol.Connection{Proto: proto(s.LocalIP), RemoteAddress: s.RemoteIP}
		key := connKey{remote: s.RemoteIP}
		if listening[s.LocalPort] {
			c.Direction, c.LocalPort = "inbound", s.LocalPort
			key.direction, key.port = "inbound", s.LocalPort
		} else {
			c.Direction, c.RemotePort = "outbound", s.RemotePort
			key.direction, key.port = "outbound", s.RemotePort
		}
		ref := resolve(s.PID)
		if ref != nil {
			key.process = ref.Name
			c.Process = &protocol.ProcessRef{Name: ref.Name, Path: ref.Path} // no PID: aggregated over time
		}
		if existing, ok := a.entries[key]; ok {
			existing.Count++
			existing.LastSeen = now
			continue
		}
		if len(a.entries) >= a.max {
			a.truncated = true
			continue
		}
		c.Count, c.FirstSeen, c.LastSeen = 1, now, now
		a.entries[key] = &c
	}
}

// Flush returns the aggregated window and starts a new one.
func (a *Aggregator) Flush(now time.Time) (conns []protocol.Connection, windowStart time.Time, truncated bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	conns = make([]protocol.Connection, 0, len(a.entries))
	for _, c := range a.entries {
		conns = append(conns, *c)
	}
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Count != conns[j].Count {
			return conns[i].Count > conns[j].Count
		}
		return conns[i].RemoteAddress < conns[j].RemoteAddress
	})
	windowStart, truncated = a.windowStart, a.truncated
	a.entries = map[connKey]*protocol.Connection{}
	a.windowStart, a.truncated = now, false
	return conns, windowStart, truncated
}

// Restore puts back the connections of a report that could not be sent
// (M39), so the next report still covers them: counts add up, first / last
// seen widen, and the window starts at the earlier start. New entries
// beyond the limit are dropped and the window is marked truncated.
func (a *Aggregator) Restore(conns []protocol.Connection, windowStart time.Time, truncated bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if windowStart.Before(a.windowStart) {
		a.windowStart = windowStart
	}
	a.truncated = a.truncated || truncated
	for _, c := range conns {
		key := connKey{direction: c.Direction, remote: c.RemoteAddress, port: c.RemotePort}
		if c.Direction == "inbound" {
			key.port = c.LocalPort
		}
		if c.Process != nil {
			key.process = c.Process.Name
		}
		if existing, ok := a.entries[key]; ok {
			existing.Count = min(existing.Count+c.Count, maxCount)
			if c.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = c.FirstSeen
			}
			if c.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = c.LastSeen
			}
			continue
		}
		if len(a.entries) >= a.max {
			a.truncated = true
			continue
		}
		restored := c
		a.entries[key] = &restored
	}
}

// maxCount: the server accepts up to a million samples per connection.
const maxCount = 1_000_000

func isRemotePeer(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return !(addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast())
}

func proto(ip string) string {
	if strings.Contains(ip, ":") {
		return "tcp6"
	}
	return "tcp"
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
