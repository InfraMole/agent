// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// siteResolver tells which IIS site a worker process serves (M42): worker
// id → application pool → the one site using that pool. The listing is
// refreshed when a worker id it does not know appears (IIS starts a new
// worker after a recycle or an idle timeout), at most once per refreshGap,
// and every refreshEvery so pool changes in the configuration show up.
type siteResolver struct {
	list func() (workers map[int32]string, poolSites map[string][]string, err error)
	now  func() time.Time
	log  *slog.Logger

	mu        sync.Mutex
	sites     map[int32]string // worker id → site ("" = shared pool or not a worker)
	refreshed time.Time
	failed    bool // the last refresh failed (logged once until it works again)
}

const (
	refreshGap   = 25 * time.Second
	refreshEvery = 10 * time.Minute
)

// resolve is a collect.SiteResolver.
func (r *siteResolver) resolve(pid int32, processName string) string {
	if pid <= 0 || !strings.EqualFold(processName, "w3wp.exe") {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	site, known := r.sites[pid]
	if known && now.Sub(r.refreshed) < refreshEvery {
		return site
	}
	if now.Sub(r.refreshed) < refreshGap {
		return site
	}
	r.refreshed = now
	workers, pools, err := r.list()
	if err != nil {
		if !r.failed {
			r.log.Warn("IIS worker processes not listed; connections are not attributed to sites", "err", err)
		}
		r.failed = true
		return site
	}
	r.failed = false
	r.sites = make(map[int32]string, len(workers)+1)
	for id, pool := range workers {
		r.sites[id] = SiteOfPool(pools, pool)
	}
	if _, ok := r.sites[pid]; !ok {
		r.sites[pid] = "" // not a worker IIS knows of: do not list again for it
	}
	return r.sites[pid]
}
