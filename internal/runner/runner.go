// SPDX-License-Identifier: AGPL-3.0-only
// Package runner implements the agent loop: sample often, report periodically.
package runner

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/InfraMole/agent/internal/client"
	"github.com/InfraMole/agent/internal/collect"
	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/inventory"
	"github.com/InfraMole/agent/internal/protocol"
)

type Options struct {
	ConfigPath string
	Version    string
	// Once: sample for Window, send a single report, exit (manual checks).
	Once   bool
	Window time.Duration
}

// Run blocks until ctx is cancelled (or, with Once, after one report).
// It returns client.ErrUnauthorized if the credential is invalid or revoked.
func Run(ctx context.Context, cfg *config.File, opts Options, log *slog.Logger) error {
	c, err := client.New(cfg.Server, cfg.InsecureDev, opts.Version)
	if err != nil {
		return err
	}
	col := collect.NewCollector(opts.Version, log)
	inv := NewInventory(cfg, log)
	conf := protocol.ClampConfig(protocol.Config{
		ReportIntervalSec: orDefault(cfg.ReportIntervalSec, protocol.DefaultReportEvery),
		SampleIntervalSec: orDefault(cfg.SampleIntervalSec, protocol.DefaultSampleEvery),
	})

	if opts.Once {
		Sample(ctx, col, opts.Window)
		report := col.Build(ctx)
		report.Inventory = inv.Due(ctx, time.Now())
		_, err := c.Report(ctx, cfg.AgentSecret, report)
		if err == nil {
			log.Info("report sent")
		}
		return err
	}

	log.Info("agent started", "server", cfg.Server, "agentId", cfg.AgentID,
		"reportEvery", conf.ReportIntervalSec, "sampleEvery", conf.SampleIntervalSec)

	// First report right away so the host shows up immediately.
	col.Sample(ctx)
	next, err := send(ctx, c, cfg, col, inv, log)
	if errors.Is(err, client.ErrUnauthorized) {
		return err
	}
	if next != nil && *next != conf {
		conf = apply(cfg, opts.ConfigPath, *next, log)
	}

	sampleT := time.NewTicker(time.Duration(conf.SampleIntervalSec) * time.Second)
	reportT := time.NewTicker(time.Duration(conf.ReportIntervalSec) * time.Second)
	defer sampleT.Stop()
	defer reportT.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("agent stopping")
			return nil
		case <-sampleT.C:
			col.Sample(ctx)
		case <-reportT.C:
			next, err := send(ctx, c, cfg, col, inv, log)
			var rl *client.RateLimitedError
			switch {
			case errors.Is(err, client.ErrUnauthorized):
				return err
			case errors.As(err, &rl):
				log.Warn("rate limited by server", "retryAfter", rl.RetryAfter)
				reportT.Reset(rl.RetryAfter)
			case err != nil:
				// The window is dropped; the next report covers a new window.
				log.Warn("report failed", "err", err)
			case next != nil && *next != conf:
				conf = apply(cfg, opts.ConfigPath, *next, log)
				sampleT.Reset(time.Duration(conf.SampleIntervalSec) * time.Second)
				reportT.Reset(time.Duration(conf.ReportIntervalSec) * time.Second)
			default:
				reportT.Reset(time.Duration(conf.ReportIntervalSec) * time.Second)
			}
		}
	}
}

// Sample takes samples every 2 s during window (used by --once and dry-run).
func Sample(ctx context.Context, col *collect.Collector, window time.Duration) {
	if window <= 0 {
		window = 10 * time.Second
	}
	deadline := time.Now().Add(window)
	for {
		col.Sample(ctx)
		if time.Now().Add(2*time.Second).After(deadline) || ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func send(ctx context.Context, c *client.Client, cfg *config.File, col *collect.Collector, inv *Inventory, log *slog.Logger) (*protocol.Config, error) {
	report := col.Build(ctx)
	report.Inventory = inv.Due(ctx, time.Now())
	next, err := c.Report(ctx, cfg.AgentSecret, report)
	if err == nil {
		log.Info("report sent", "connections", len(report.Connections), "listeners", len(report.Listeners),
			"services", len(report.Services), "truncated", report.Truncated, "inventory", report.Inventory != nil)
	} else if report.Inventory != nil {
		inv.Retry() // the inventory was lost with the report
	}
	return next, err
}

// Inventory runs the configured collectors on their own (slow) cadence and
// attaches the result to the next report. Nil-safe: no collectors → no-op.
type Inventory struct {
	proxmox  *inventory.Proxmox
	interval time.Duration
	last     time.Time
	log      *slog.Logger
}

func NewInventory(cfg *config.File, log *slog.Logger) *Inventory {
	if cfg.Collectors == nil || cfg.Collectors.Proxmox == nil {
		return nil
	}
	p, err := inventory.NewProxmox(*cfg.Collectors.Proxmox)
	if err != nil {
		log.Warn("proxmox collector disabled", "err", err)
		return nil
	}
	log.Info("proxmox collector enabled", "every", cfg.Collectors.Proxmox.Interval())
	return &Inventory{proxmox: p, interval: cfg.Collectors.Proxmox.Interval(), log: log}
}

// Due collects when the interval has elapsed. Failures are logged and retried
// at the next interval (they never block the host report).
func (i *Inventory) Due(ctx context.Context, now time.Time) *protocol.Inventory {
	if i == nil || (!i.last.IsZero() && now.Sub(i.last) < i.interval) {
		return nil
	}
	i.last = now
	out, err := i.proxmox.Collect(ctx)
	if err != nil {
		i.log.Warn("proxmox inventory failed", "err", err)
		return nil
	}
	return out
}

func (i *Inventory) Retry() {
	if i != nil {
		i.last = time.Time{}
	}
}

// apply persists server-provided (already clamped) config so restarts keep it.
func apply(cfg *config.File, path string, next protocol.Config, log *slog.Logger) protocol.Config {
	cfg.ReportIntervalSec, cfg.SampleIntervalSec = next.ReportIntervalSec, next.SampleIntervalSec
	if path != "" {
		if err := config.Save(path, cfg); err != nil {
			log.Warn("could not persist config", "err", err)
		}
	}
	log.Info("config updated", "reportEvery", next.ReportIntervalSec, "sampleEvery", next.SampleIntervalSec)
	return next
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
