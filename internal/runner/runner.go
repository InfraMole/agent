// SPDX-License-Identifier: AGPL-3.0-only
// Package runner implements the agent loop: sample often, report periodically.
package runner

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/InfraMole/agent/internal/client"
	"github.com/InfraMole/agent/internal/collect"
	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/inventory"
	"github.com/InfraMole/agent/internal/protocol"
	"github.com/InfraMole/agent/internal/update"
	"github.com/InfraMole/agent/internal/workloads"
)

// ErrRestart asks the caller to exit so the service manager starts the
// (new or restored) binary: after a self-update or an update rollback.
var ErrRestart = errors.New("restart required")

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
	wl := &serverWorkloads{col: workloads.New(cfg.Collectors, log)}
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
		"reportEvery", conf.ReportIntervalSec, "sampleEvery", conf.SampleIntervalSec, "version", opts.Version)

	// M22: a freshly updated binary that keeps failing is rolled back here.
	exe, _ := os.Executable()
	if rolled, err := update.OnStart(exe); err != nil {
		log.Warn("update state", "err", err)
	} else if rolled {
		log.Error("the updated agent never reported successfully; the previous version was restored")
		return ErrRestart
	}
	confirmed := false
	updates := newAutoUpdater(cfg, opts.Version, log)

	// First report right away so the host shows up immediately.
	col.Sample(ctx)
	next, err := send(ctx, c, cfg, col, inv, wl, log)
	if errors.Is(err, client.ErrUnauthorized) {
		return err
	}
	if err == nil {
		update.Confirm(exe)
		confirmed = true
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
		case <-updates.timer():
			if updates.run(ctx) {
				return ErrRestart
			}
		case <-sampleT.C:
			col.Sample(ctx)
		case <-reportT.C:
			next, err := send(ctx, c, cfg, col, inv, wl, log)
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
			case !confirmed:
				update.Confirm(exe)
				confirmed = true
				if next != nil && *next != conf {
					conf = apply(cfg, opts.ConfigPath, *next, log)
					sampleT.Reset(time.Duration(conf.SampleIntervalSec) * time.Second)
					reportT.Reset(time.Duration(conf.ReportIntervalSec) * time.Second)
				} else {
					reportT.Reset(time.Duration(conf.ReportIntervalSec) * time.Second)
				}
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

func send(ctx context.Context, c *client.Client, cfg *config.File, col *collect.Collector, inv *Inventory, wl *serverWorkloads, log *slog.Logger) (*protocol.Config, error) {
	report := col.Build(ctx)
	report.Inventory = inv.Due(ctx, time.Now())
	report.Hypervisors = inv.DueHypervisors(ctx, time.Now(), false)
	report.Workloads = wl.due(ctx, time.Now())
	res, err := c.Report(ctx, cfg.AgentSecret, report)
	if err != nil {
		if report.Inventory != nil {
			inv.Retry() // the inventory was lost with the report
		}
		if len(report.Hypervisors) > 0 {
			if errors.Is(err, client.ErrRejected) {
				inv.hvDisabled = true
				log.Warn("server rejected the hypervisors section; not sending it again until restart", "err", err)
			} else {
				inv.RetryHypervisors(report.Hypervisors)
			}
		}
		if report.Workloads != nil {
			if errors.Is(err, client.ErrRejected) {
				// Never let workloads block host reports: stop sending them
				// for this run (the next report goes out without them).
				wl.accepted, wl.disabled = false, true
				log.Warn("server rejected the workloads section; not sending it again until restart", "err", err)
			} else {
				wl.col.Retry()
			}
		}
		return nil, err
	}
	wl.accepted = !wl.disabled && hasFeature(res.Features, protocol.FeatureWorkloads)
	wl.linux = hasFeature(res.Features, protocol.FeatureWorkloadsLinux)
	inv.negotiated(res.Features)
	log.Info("report sent", "connections", len(report.Connections), "listeners", len(report.Listeners),
		"services", len(report.Services), "truncated", report.Truncated, "inventory", report.Inventory != nil, "hypervisors", len(report.Hypervisors),
		"workloads", report.Workloads != nil)
	return &res.Config, nil
}

// serverWorkloads sends workloads only once the server has said it accepts
// them (M16): an older server rejects unknown report fields, so the first
// report of a run never carries them.
type serverWorkloads struct {
	col      *workloads.Collector
	accepted bool
	linux    bool // the server also accepts the Linux fields (M20)
	disabled bool // the server rejected them once in this run
}

func (w *serverWorkloads) due(ctx context.Context, now time.Time) *protocol.Workloads {
	if w == nil || !w.accepted {
		return nil
	}
	out := w.col.Due(ctx, now)
	if out != nil && !w.linux {
		// A 0.5–0.7 server knows only the Windows fields.
		out.NginxSites, out.ApacheSites, out.PostgresDatabases, out.MySQLDatabases = nil, nil, nil, nil
		if out.IISSites == nil && out.SQLDatabases == nil {
			return nil
		}
	}
	return out
}

func hasFeature(features []string, name string) bool {
	for _, f := range features {
		if f == name {
			return true
		}
	}
	return false
}

// Inventory runs the configured collectors on their own (slow) cadence and
// attaches the result to the next report. Nil-safe: no collectors → no-op.
type Inventory struct {
	proxmox  *inventory.Proxmox
	interval time.Duration
	last     time.Time
	// M24: hypervisor collectors, sent only once the server lists
	// "hypervisors" in its features (an older server rejects the field).
	hypervisors []*hypervisorCollector
	hvAccepted  bool
	hvDisabled  bool // the server rejected the section once in this run
	log         *slog.Logger
}

type hypervisorCollector struct {
	source   string
	collect  func(context.Context) (*protocol.Hypervisor, error)
	interval time.Duration
	last     time.Time
}

func NewInventory(cfg *config.File, log *slog.Logger) *Inventory {
	c := cfg.Collectors
	if c == nil {
		return nil
	}
	inv := &Inventory{log: log}
	if c.Proxmox != nil {
		if p, err := inventory.NewProxmox(*c.Proxmox); err != nil {
			log.Warn("proxmox collector disabled", "err", err)
		} else {
			log.Info("proxmox collector enabled", "every", c.Proxmox.Interval())
			inv.proxmox, inv.interval = p, c.Proxmox.Interval()
		}
	}
	add := func(source string, every int, collect func(context.Context) (*protocol.Hypervisor, error), err error) {
		if err != nil {
			log.Warn(source+" collector disabled", "err", err)
			return
		}
		interval := config.ClampInterval(every)
		log.Info(source+" collector enabled", "every", interval)
		inv.hypervisors = append(inv.hypervisors, &hypervisorCollector{source: source, collect: collect, interval: interval})
	}
	if c.VCenter != nil {
		v, err := inventory.NewVCenter(*c.VCenter)
		add("vcenter", c.VCenter.IntervalSec, func(ctx context.Context) (*protocol.Hypervisor, error) { return v.Collect(ctx) }, err)
	}
	if c.XenOrchestra != nil {
		x, err := inventory.NewXenOrchestra(*c.XenOrchestra)
		add("xenorchestra", c.XenOrchestra.IntervalSec, func(ctx context.Context) (*protocol.Hypervisor, error) { return x.Collect(ctx) }, err)
	}
	if c.HyperV != nil {
		h, err := inventory.NewHyperV()
		add("hyperv", c.HyperV.IntervalSec, func(ctx context.Context) (*protocol.Hypervisor, error) { return h.Collect(ctx) }, err)
	}
	if inv.proxmox == nil && len(inv.hypervisors) == 0 {
		return nil
	}
	return inv
}

// Due collects when the interval has elapsed. Failures are logged and retried
// at the next interval (they never block the host report).
func (i *Inventory) Due(ctx context.Context, now time.Time) *protocol.Inventory {
	if i == nil || i.proxmox == nil || (!i.last.IsZero() && now.Sub(i.last) < i.interval) {
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

// DueHypervisors runs the hypervisor collectors whose interval has elapsed.
// force: dry-run (no server to negotiate with).
func (i *Inventory) DueHypervisors(ctx context.Context, now time.Time, force bool) []protocol.Hypervisor {
	if i == nil || (!force && (!i.hvAccepted || i.hvDisabled)) {
		return nil
	}
	var out []protocol.Hypervisor
	for _, h := range i.hypervisors {
		if !h.last.IsZero() && now.Sub(h.last) < h.interval {
			continue
		}
		h.last = now
		inv, err := h.collect(ctx)
		if err != nil {
			i.log.Warn(h.source+" inventory failed", "err", err)
			continue
		}
		out = append(out, *inv)
	}
	return out
}

// RetryHypervisors: the collections were lost with a failed report.
func (i *Inventory) RetryHypervisors(sent []protocol.Hypervisor) {
	if i == nil {
		return
	}
	for _, s := range sent {
		for _, h := range i.hypervisors {
			if h.source == s.Source {
				h.last = time.Time{}
			}
		}
	}
}

// negotiated records what the server accepts (from the report response).
func (i *Inventory) negotiated(features []string) {
	if i != nil {
		i.hvAccepted = hasFeature(features, protocol.FeatureHypervisors)
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
