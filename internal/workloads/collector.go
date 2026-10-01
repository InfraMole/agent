// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

// Collector gathers workloads on a slow cadence (default hourly) and hands
// them to the next report. Nil-safe: nil means "nothing to collect here".
type Collector struct {
	web      bool // IIS on Windows; nginx and Apache on Linux
	mssql    bool
	postgres bool
	mysql    bool
	docker   bool
	interval time.Duration
	last     time.Time
	log      *slog.Logger
}

// New returns nil on hosts without anything to collect (unsupported OS, or
// every workload collector disabled in the local config).
func New(c *config.Collectors, log *slog.Logger) *Collector {
	if !Supported {
		return nil
	}
	col := &Collector{
		web:      c.WebServersEnabled(),
		mssql:    c.SQLServerEnabled() && onWindows,
		postgres: c.PostgreSQLEnabled() && onLinux,
		mysql:    c.MySQLEnabled() && onLinux,
		docker:   c.DockerEnabled() && onLinux,
		interval: c.WorkloadsInterval(),
		log:      log,
	}
	if !col.web && !col.mssql && !col.postgres && !col.mysql && !col.docker {
		return nil
	}
	return col
}

// Due collects when the interval has elapsed. Each kind is independent: a
// failure leaves that kind out (the server then keeps what it knew) and is
// logged locally; it never blocks the host report. A kind whose software is
// not installed is left out too.
func (c *Collector) Due(ctx context.Context, now time.Time) *protocol.Workloads {
	if c == nil || (!c.last.IsZero() && now.Sub(c.last) < c.interval) {
		return nil
	}
	c.last = now
	out := &protocol.Workloads{CollectedAt: now.UTC().Truncate(time.Second)}
	if c.web {
		out.IISSites = c.sites("IIS sites", iisSites)
		out.NginxSites = c.sites("nginx sites", nginxSites)
		out.ApacheSites = c.sites("Apache sites", apacheSites)
		out.HAProxySites = c.sites("HAProxy frontends", haproxySites)
	}
	if c.mssql {
		out.SQLDatabases = c.databases(ctx, "SQL Server databases", func(ctx context.Context) ([]protocol.Database, bool, error) {
			dbs, err := sqlDatabases(ctx)
			return dbs, true, err
		})
	}
	if c.postgres {
		out.PostgresDatabases = c.databases(ctx, "PostgreSQL databases", postgresDatabases)
	}
	if c.mysql {
		out.MySQLDatabases = c.databases(ctx, "MySQL databases", mysqlDatabases)
	}
	if c.docker {
		out.Containers = c.containers(ctx)
	}
	if out.IISSites == nil && out.SQLDatabases == nil && !out.HasLinux() && out.Containers == nil {
		return nil
	}
	return out
}

func (c *Collector) sites(label string, collect func() ([]protocol.WebSite, bool, error)) *[]protocol.WebSite {
	sites, found, err := collect()
	switch {
	case err != nil:
		c.log.Warn(label+" not collected", "err", err)
		return nil
	case !found:
		return nil
	}
	if sites == nil {
		sites = []protocol.WebSite{} // "collected, none" must encode as [], not null
	}
	if len(sites) > protocol.MaxIISSites {
		sites = sites[:protocol.MaxIISSites]
	}
	return &sites
}

func (c *Collector) databases(
	ctx context.Context,
	label string,
	collect func(context.Context) ([]protocol.Database, bool, error),
) *[]protocol.Database {
	dbs, found, err := collect(ctx)
	switch {
	case err != nil:
		c.log.Warn(label+" not collected", "err", err)
		return nil
	case !found:
		return nil
	}
	sort.Slice(dbs, func(i, j int) bool {
		if dbs[i].Instance != dbs[j].Instance {
			return dbs[i].Instance < dbs[j].Instance
		}
		return dbs[i].Name < dbs[j].Name
	})
	if len(dbs) > protocol.MaxSQLDatabases {
		dbs = dbs[:protocol.MaxSQLDatabases]
	}
	if dbs == nil {
		dbs = []protocol.Database{} // "collected, none" must encode as [], not null
	}
	return &dbs
}

func (c *Collector) containers(ctx context.Context) *[]protocol.Container {
	list, found, err := dockerContainers(ctx)
	switch {
	case err != nil:
		c.log.Warn("Docker containers not collected", "err", err)
		return nil
	case !found:
		return nil
	}
	return &list // never nil: toContainers returns []
}

// Retry makes the next report collect again (the last result was lost).
func (c *Collector) Retry() {
	if c != nil {
		c.last = time.Time{}
	}
}
