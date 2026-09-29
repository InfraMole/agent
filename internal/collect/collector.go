// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

// Collector samples the TCP table periodically and builds reports.
type Collector struct {
	version string
	agg     *Aggregator
	log     *slog.Logger

	mu        sync.Mutex
	listeners []protocol.Listener // from the most recent sample
}

func NewCollector(version string, log *slog.Logger) *Collector {
	return &Collector{version: version, agg: NewAggregator(time.Now().UTC()), log: log, listeners: []protocol.Listener{}}
}

// Sample reads the TCP table once and folds it into the current window.
func (c *Collector) Sample(ctx context.Context) {
	sockets, err := Sockets(ctx)
	if err != nil {
		c.log.Warn("sample sockets", "err", err)
		return
	}
	resolve := NewProcessResolver(ctx)
	now := time.Now().UTC()
	c.agg.Add(sockets, resolve, now)
	listeners := Listeners(sockets, resolve)
	c.mu.Lock()
	c.listeners = listeners
	c.mu.Unlock()
}

// Build assembles a report from fresh host facts and the aggregated window,
// then starts a new window. Collection errors degrade to empty sections.
func (c *Collector) Build(ctx context.Context) protocol.Report {
	now := time.Now().UTC()
	h, _, err := HostInfo(ctx)
	if err != nil {
		c.log.Warn("host info", "err", err)
	}
	ifaces, err := Interfaces(ctx)
	if err != nil {
		c.log.Warn("interfaces", "err", err)
	}
	services, err := Services(ctx)
	if err != nil {
		c.log.Warn("services", "err", err)
	}
	c.mu.Lock()
	listeners := c.listeners
	c.mu.Unlock()
	conns, windowStart, truncated := c.agg.Flush(now)

	return Assemble(c.version, now, windowStart, h, ifaces, services, listeners, conns, truncated)
}

// Assemble applies the protocol limits and guarantees non-nil slices (the
// server expects arrays, never null). Pure, unit tested.
func Assemble(
	version string, now, windowStart time.Time, h protocol.Host,
	ifaces []protocol.Interface, services []protocol.Service,
	listeners []protocol.Listener, conns []protocol.Connection, truncated bool,
) protocol.Report {
	r := protocol.Report{
		SchemaVersion: protocol.SchemaVersion,
		AgentVersion:  version,
		CollectedAt:   now,
		WindowStart:   windowStart,
		Host:          h,
		Interfaces:    nonNil(ifaces),
		Services:      nonNil(services),
		Listeners:     nonNil(listeners),
		Connections:   nonNil(conns),
		Truncated:     truncated,
	}
	if len(r.Interfaces) > protocol.MaxInterfaces {
		r.Interfaces, r.Truncated = r.Interfaces[:protocol.MaxInterfaces], true
	}
	if len(r.Services) > protocol.MaxServices {
		r.Services, r.Truncated = r.Services[:protocol.MaxServices], true
	}
	if len(r.Listeners) > protocol.MaxListeners {
		r.Listeners, r.Truncated = r.Listeners[:protocol.MaxListeners], true
	}
	if len(r.Connections) > protocol.MaxConnections {
		r.Connections, r.Truncated = r.Connections[:protocol.MaxConnections], true
	}
	if r.Host.Hostname == "" {
		r.Host.Hostname = "unknown"
	}
	if r.Host.OSName == "" {
		r.Host.OSName = r.Host.OS
	}
	return r
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
