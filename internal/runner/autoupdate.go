// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/update"
)

// ServiceName is the OS service the agent runs as (set by main).
var ServiceName = "inframole-agent"

// autoUpdater checks for a newer signed release about once a day (M22,
// ADR-033), with jitter so a fleet does not check at the same second. Nil
// (and its timer channel nil, which never fires) unless autoUpdate is on.
type autoUpdater struct {
	u   *update.Updater
	t   *time.Timer
	log *slog.Logger
}

func newAutoUpdater(cfg *config.File, version string, log *slog.Logger) *autoUpdater {
	if !cfg.AutoUpdate {
		return nil
	}
	if cfg.UpdateBaseURL != "" && !strings.HasPrefix(cfg.UpdateBaseURL, "https://") && !cfg.InsecureDev {
		log.Warn("self-update disabled: updateBaseUrl must be https")
		return nil
	}
	u, err := update.New(cfg.UpdateBaseURL, version)
	if err != nil {
		log.Warn("self-update disabled", "err", err)
		return nil
	}
	first := 10*time.Minute + time.Duration(rand.Int64N(int64(time.Hour)))
	log.Info("self-update enabled", "firstCheckIn", first.Round(time.Minute))
	return &autoUpdater{u: u, t: time.NewTimer(first), log: log}
}

func (a *autoUpdater) timer() <-chan time.Time {
	if a == nil {
		return nil
	}
	return a.t.C
}

// run checks and, if a newer release verifies, installs it. true = the new
// binary is in place and the agent must restart.
func (a *autoUpdater) run(ctx context.Context) bool {
	defer a.t.Reset(23*time.Hour + time.Duration(rand.Int64N(int64(2*time.Hour))))
	plan, err := a.u.Check(ctx)
	if err != nil {
		a.log.Warn("update check failed", "err", err)
		return false
	}
	if plan == nil {
		return false
	}
	a.log.Info("installing update", "from", a.u.Current, "to", plan.Version)
	if err := a.u.Apply(ctx, plan); err != nil {
		a.log.Error("update not installed", "err", err)
		return false
	}
	if err := update.EnsureServiceRestart(ServiceName); err != nil {
		a.log.Warn("could not make the service restart on exit", "err", err)
	}
	a.log.Info("update installed; restarting", "version", plan.Version)
	return true
}
