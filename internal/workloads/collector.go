// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/health"
	"github.com/InfraMole/agent/internal/protocol"
)

// Collector gathers workloads on a slow cadence (default hourly) and hands
// them to the next report. Nil-safe: nil means "nothing to collect here".
type Collector struct {
	web      bool // IIS on Windows; nginx and Apache on Linux
	mssql    bool
	clients  bool // SQL Server database clients (M42)
	postgres bool
	mysql    bool
	pgUsers  bool // PostgreSQL database clients (M45)
	myUsers  bool // MySQL / MariaDB database clients (M45)
	docker   bool
	interval time.Duration
	last     time.Time
	log      *slog.Logger
	issues   health.Set // outcome of the latest collection of each kind (M39)
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
		clients:  c.SQLServerClientsEnabled() && onWindows,
		postgres: c.PostgreSQLEnabled() && onLinux,
		mysql:    c.MySQLEnabled() && onLinux,
		pgUsers:  c.PostgreSQLClientsEnabled() && onLinux,
		myUsers:  c.MySQLClientsEnabled() && onLinux,
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
// failure leaves that kind out (the server then keeps what it knew), is
// logged locally and kept in Issues until that kind succeeds; it never
// blocks the host report. A kind whose software is not installed is left
// out too, without an issue.
func (c *Collector) Due(ctx context.Context, now time.Time) *protocol.Workloads {
	if c == nil || (!c.last.IsZero() && now.Sub(c.last) < c.interval) {
		return nil
	}
	c.last = now
	out := &protocol.Workloads{CollectedAt: now.UTC().Truncate(time.Second)}
	if c.web {
		out.IISSites = c.sites(protocol.CollectorIIS, "IIS sites", iisSites)
		out.NginxSites = c.sites(protocol.CollectorNginx, "nginx sites", nginxSites)
		out.ApacheSites = c.sites(protocol.CollectorApache, "Apache sites", apacheSites)
		out.HAProxySites = c.sites(protocol.CollectorHAProxy, "HAProxy frontends", haproxySites)
	}
	if c.mssql {
		out.SQLDatabases = c.databases(ctx, protocol.CollectorSQLServer, "SQL Server databases", func(ctx context.Context) ([]protocol.Database, bool, error) {
			dbs, err := sqlDatabases(ctx)
			return dbs, true, err
		})
	}
	if c.postgres {
		out.PostgresDatabases = c.databases(ctx, protocol.CollectorPostgreSQL, "PostgreSQL databases", postgresDatabases)
	}
	if c.mysql {
		out.MySQLDatabases = c.databases(ctx, protocol.CollectorMySQL, "MySQL databases", mysqlDatabases)
	}
	if c.docker {
		out.Containers = c.containers(ctx)
	}
	if out.IISSites == nil && out.SQLDatabases == nil && !out.HasLinux() && out.Containers == nil {
		return nil
	}
	return out
}

// Issues: the kinds whose latest collection failed (nil-safe).
func (c *Collector) Issues() []protocol.Issue {
	if c == nil {
		return nil
	}
	return c.issues.List()
}

func (c *Collector) sites(collector, label string, collect func() ([]protocol.WebSite, bool, error)) *[]protocol.WebSite {
	sites, found, err := collect()
	c.issues.Record(collector, err)
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
	collector, label string,
	collect func(context.Context) ([]protocol.Database, bool, error),
) *[]protocol.Database {
	dbs, found, err := collect(ctx)
	c.issues.Record(collector, err)
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
	c.issues.Record(protocol.CollectorDocker, err)
	switch {
	case err != nil:
		c.log.Warn("Docker containers not collected", "err", err)
		return nil
	case !found:
		return nil
	}
	return &list // never nil: toContainers returns []
}

// DatabaseClients (M42, M45): who has sessions open to the local SQL
// Server, PostgreSQL and MySQL / MariaDB databases right now — collected for
// every report, not on the workloads cadence, since sessions come and go.
// linux: the server accepts the PostgreSQL and MySQL engines (M45). nil when
// no engine was collected: disabled, not installed, or failed (then kept in
// Issues); one engine failing leaves the others in.
func (c *Collector) DatabaseClients(ctx context.Context, linux bool) *[]protocol.DatabaseClient {
	if c == nil {
		return nil
	}
	engines := []struct {
		on        bool
		collector string
		label     string
		collect   func(context.Context) ([]protocol.DatabaseClient, bool, error)
	}{
		{c.clients, protocol.CollectorSQLClients, "SQL Server", sqlClients},
		{c.pgUsers && linux, protocol.CollectorPostgreSQLClients, "PostgreSQL", postgresClients},
		{c.myUsers && linux, protocol.CollectorMySQLClients, "MySQL", mysqlClients},
	}
	var list []protocol.DatabaseClient
	collected := false
	for _, e := range engines {
		if !e.on {
			continue
		}
		got, found, err := e.collect(ctx)
		c.issues.Record(e.collector, err)
		switch {
		case err != nil:
			c.log.Warn(e.label+" database clients not collected", "err", err)
		case found:
			collected = true
			list = append(list, got...)
		}
	}
	if !collected {
		return nil
	}
	sortClients(list)
	if len(list) > protocol.MaxDatabaseClients {
		list = list[:protocol.MaxDatabaseClients]
	}
	if list == nil {
		list = []protocol.DatabaseClient{} // "collected, none" must encode as [], not null
	}
	return &list
}

// Retry makes the next report collect again (the last result was lost).
func (c *Collector) Retry() {
	if c != nil {
		c.last = time.Time{}
	}
}
