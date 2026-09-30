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
	iis      bool
	sql      bool
	interval time.Duration
	last     time.Time
	log      *slog.Logger
}

// New returns nil on hosts without anything to collect (not Windows, or
// every workload collector disabled in the local config).
func New(c *config.Collectors, log *slog.Logger) *Collector {
	if !Supported {
		return nil
	}
	col := &Collector{iis: c.IISEnabled(), sql: c.SQLServerEnabled(), interval: c.WorkloadsInterval(), log: log}
	if !col.iis && !col.sql {
		return nil
	}
	return col
}

// Due collects when the interval has elapsed. Each kind is independent: a
// failure leaves that kind out (the server then keeps what it knew) and is
// logged locally; it never blocks the host report.
func (c *Collector) Due(ctx context.Context, now time.Time) *protocol.Workloads {
	if c == nil || (!c.last.IsZero() && now.Sub(c.last) < c.interval) {
		return nil
	}
	c.last = now
	out := &protocol.Workloads{CollectedAt: now.UTC().Truncate(time.Second)}
	if c.iis {
		sites, found, err := iisSites()
		switch {
		case err != nil:
			c.log.Warn("IIS sites not collected", "err", err)
		case found:
			if sites == nil {
				sites = []protocol.IISSite{} // "collected, none" must encode as [], not null
			}
			out.IISSites = &sites
		}
	}
	if c.sql {
		dbs, err := sqlDatabases(ctx)
		if err != nil {
			c.log.Warn("SQL Server databases not collected", "err", err)
		} else {
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
				dbs = []protocol.SQLDatabase{} // "collected, none" must encode as [], not null
			}
			out.SQLDatabases = &dbs
		}
	}
	if out.IISSites == nil && out.SQLDatabases == nil {
		return nil
	}
	return out
}

// Retry makes the next report collect again (the last result was lost).
func (c *Collector) Retry() {
	if c != nil {
		c.last = time.Time{}
	}
}
