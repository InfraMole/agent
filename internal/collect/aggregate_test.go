// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

func resolver(names map[int32]string) ProcessResolver {
	return func(pid int32) *protocol.ProcessRef {
		if n, ok := names[pid]; ok {
			return &protocol.ProcessRef{Name: n, PID: pid}
		}
		return nil
	}
}

var procs = resolver(map[int32]string{10: "w3wp.exe", 20: "sqlservr.exe"})

func TestListenersDedupAndSort(t *testing.T) {
	sockets := []Socket{
		{LocalIP: "0.0.0.0", LocalPort: 443, Status: "LISTEN", PID: 10},
		{LocalIP: "0.0.0.0", LocalPort: 443, Status: "LISTEN", PID: 10},
		{LocalIP: "::", LocalPort: 80, Status: "LISTEN", PID: 10},
		{LocalIP: "10.0.0.23", LocalPort: 50000, RemoteIP: "10.0.0.40", RemotePort: 1433, Status: "ESTABLISHED"},
	}
	got := Listeners(sockets, procs)
	if len(got) != 2 || got[0].Port != 80 || got[0].Proto != "tcp6" || got[1].Port != 443 {
		t.Fatalf("unexpected listeners: %+v", got)
	}
	if got[1].Process == nil || got[1].Process.Name != "w3wp.exe" {
		t.Fatalf("process not resolved: %+v", got[1])
	}
}

func TestAggregatorDirectionFilteringAndCounting(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := NewAggregator(t0)
	sample := []Socket{
		{LocalIP: "0.0.0.0", LocalPort: 443, Status: "LISTEN"},
		// outbound to SQL (ephemeral local port)
		{LocalIP: "10.0.0.23", LocalPort: 50001, RemoteIP: "10.0.0.40", RemotePort: 1433, Status: "ESTABLISHED", PID: 10},
		// same flow, another ephemeral port -> same aggregate
		{LocalIP: "10.0.0.23", LocalPort: 50002, RemoteIP: "10.0.0.40", RemotePort: 1433, Status: "ESTABLISHED", PID: 10},
		// inbound HTTPS client
		{LocalIP: "10.0.0.23", LocalPort: 443, RemoteIP: "10.0.1.5", RemotePort: 61000, Status: "ESTABLISHED"},
		// noise: loopback, link-local, not established, IPv4-mapped loopback
		{LocalIP: "127.0.0.1", LocalPort: 5000, RemoteIP: "127.0.0.1", RemotePort: 5001, Status: "ESTABLISHED"},
		{LocalIP: "fe80::2", LocalPort: 5000, RemoteIP: "fe80::3", RemotePort: 5001, Status: "ESTABLISHED"},
		{LocalIP: "10.0.0.23", LocalPort: 50003, RemoteIP: "10.0.0.50", RemotePort: 80, Status: "TIME_WAIT"},
		{LocalIP: "::ffff:127.0.0.1", LocalPort: 5000, RemoteIP: "::ffff:127.0.0.1", RemotePort: 5001, Status: "ESTABLISHED"},
	}
	a.Add(sample, procs, t0)
	a.Add(sample, procs, t0.Add(30*time.Second))

	conns, windowStart, truncated := a.Flush(t0.Add(time.Minute))
	if !windowStart.Equal(t0) || truncated {
		t.Fatalf("window %v truncated %v", windowStart, truncated)
	}
	if len(conns) != 2 {
		t.Fatalf("want 2 aggregated connections, got %+v", conns)
	}
	out := conns[0]
	if out.Direction != "outbound" || out.RemotePort != 1433 || out.LocalPort != 0 || out.Count != 4 ||
		out.Process == nil || out.Process.Name != "w3wp.exe" || out.Process.PID != 0 {
		t.Fatalf("bad outbound aggregate: %+v", out)
	}
	if !out.FirstSeen.Equal(t0) || !out.LastSeen.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("bad first/last seen: %+v", out)
	}
	in := conns[1]
	if in.Direction != "inbound" || in.LocalPort != 443 || in.RemotePort != 0 || in.Count != 2 {
		t.Fatalf("bad inbound aggregate: %+v", in)
	}

	// Flush starts a new, empty window.
	next, start2, _ := a.Flush(t0.Add(2 * time.Minute))
	if len(next) != 0 || !start2.Equal(t0.Add(time.Minute)) {
		t.Fatalf("flush did not reset: %+v %v", next, start2)
	}
}

func TestAggregatorTruncates(t *testing.T) {
	a := NewAggregator(time.Now())
	a.max = 2
	var sockets []Socket
	for i := 1; i <= 5; i++ {
		sockets = append(sockets, Socket{LocalIP: "10.0.0.1", LocalPort: 40000, RemoteIP: "10.0.0." + itoa(uint32(10+i)), RemotePort: 80, Status: "ESTABLISHED"})
	}
	a.Add(sockets, procs, time.Now())
	conns, _, truncated := a.Flush(time.Now())
	if len(conns) != 2 || !truncated {
		t.Fatalf("want 2 conns + truncated, got %d %v", len(conns), truncated)
	}
}
