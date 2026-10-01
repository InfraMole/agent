// SPDX-License-Identifier: AGPL-3.0-only
// Command inframole-agent is InfraMole's read-only discovery agent (docs/AGENT.md).
//
// It collects host facts, running services, listening ports and TCP
// connections, and reports them over HTTPS. It has NO remote command channel.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/InfraMole/agent/internal/client"
	"github.com/InfraMole/agent/internal/collect"
	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
	"github.com/InfraMole/agent/internal/runner"
	"github.com/InfraMole/agent/internal/update"
	"github.com/InfraMole/agent/internal/workloads"
)

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "0.1.0-dev"

const serviceName = "inframole-agent"

const usage = `inframole-agent — read-only infrastructure discovery agent

Usage:
  inframole-agent dry-run [--window 10s] [--inventory] Print the report that WOULD be sent. Nothing is sent
                                                   (--inventory also calls the local collectors).
  inframole-agent enroll  --server URL --token TOKEN  Enroll this machine and write the config file.
  inframole-agent run     [--once] [--window 10s]     Run in the foreground (--once: one report, then exit).
  inframole-agent install --server URL --token TOKEN  Enroll + install and start the OS service (admin/root).
  inframole-agent uninstall [--keep-config]           Stop and remove the service and its config (admin/root).
  inframole-agent status                              Show enrollment and service status.
  inframole-agent update  [--check]                   Install the newest signed release now (admin/root);
                                                   --check only reports whether one exists.
  inframole-agent version

Common flags:
  --config PATH     Config file (default: %s)
  --insecure-dev    Allow http:// servers (local testing only)

The enrollment token can also be given via INFRAMOLE_ENROLLMENT_TOKEN (keeps it
out of shell history).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, config.DefaultPath())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("inframole-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "dry-run":
		err = cmdDryRun(args)
	case "enroll":
		err = cmdEnroll(args)
	case "run":
		err = cmdRun(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "update":
		err = cmdUpdate(args)
	case "help", "--help", "-h":
		fmt.Printf(usage, config.DefaultPath())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, config.DefaultPath())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type commonFlags struct {
	configPath  string
	server      string
	token       string
	insecureDev bool
	window      time.Duration
	once        bool
	keepConfig  bool
	inventory   bool
	check       bool
}

func parse(name string, args []string, extra func(*flag.FlagSet, *commonFlags)) (*commonFlags, error) {
	f := &commonFlags{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&f.configPath, "config", config.DefaultPath(), "config file path")
	if extra != nil {
		extra(fs, f)
	}
	return f, fs.Parse(args)
}

func enrollFlags(fs *flag.FlagSet, f *commonFlags) {
	fs.StringVar(&f.server, "server", "", "InfraMole base URL, e.g. https://app.example.com")
	fs.StringVar(&f.token, "token", os.Getenv("INFRAMOLE_ENROLLMENT_TOKEN"), "enrollment token (dmp_enr_…)")
	fs.BoolVar(&f.insecureDev, "insecure-dev", false, "allow http:// (local testing only)")
}

func logger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ───────────────────────── commands ─────────────────────────

func cmdDryRun(args []string) error {
	f, err := parse("dry-run", args, func(fs *flag.FlagSet, f *commonFlags) {
		fs.DurationVar(&f.window, "window", 10*time.Second, "sampling window")
		fs.BoolVar(&f.inventory, "inventory", false, "also run the collectors configured in the config file")
	})
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	log := logger(os.Stderr)
	var inv *runner.Inventory
	if f.inventory {
		cfg, err := config.Read(f.configPath)
		if err != nil {
			return fmt.Errorf("read config for --inventory: %w", err)
		}
		if inv = runner.NewInventory(cfg, log); inv == nil {
			return errors.New("no usable collector in the config file (see docs/AGENT.md)")
		}
	}
	col := collect.NewCollector(version, log)
	fmt.Fprintf(os.Stderr, "Sampling for %s (nothing is sent to InfraMole)…\n", f.window)
	runner.Sample(ctx, col, f.window)
	report := col.Build(ctx)
	report.Inventory = inv.Due(ctx, time.Now())
	report.Hypervisors = inv.DueHypervisors(ctx, time.Now(), true)
	report.Kubernetes = inv.DueKubernetes(ctx, time.Now(), true)
	// Workloads (IIS sites; SQL Server if enabled in the config) are always
	// shown here, so you can see them before any server receives them.
	var collectors *config.Collectors
	if cfg, err := config.Read(f.configPath); err == nil {
		collectors = cfg.Collectors
	}
	report.Workloads = workloads.New(collectors, log).Due(ctx, time.Now())
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func cmdEnroll(args []string) error {
	f, err := parse("enroll", args, enrollFlags)
	if err != nil {
		return err
	}
	return enroll(f)
}

func enroll(f *commonFlags) error {
	if f.server == "" || f.token == "" {
		return errors.New("--server and --token (or INFRAMOLE_ENROLLMENT_TOKEN) are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := client.New(f.server, f.insecureDev, version)
	if err != nil {
		return err
	}
	host, machineID, err := collect.HostInfo(ctx)
	if err != nil {
		return fmt.Errorf("read host info: %w", err)
	}
	if len(machineID) < 8 {
		return errors.New("could not determine a stable machine id")
	}
	res, err := c.Enroll(ctx, protocol.EnrollRequest{
		EnrollmentToken: f.token,
		MachineID:       machineID,
		Hostname:        host.Hostname,
		OS:              runtime.GOOS,
		OSVersion:       firstNonEmpty(host.OSVersion, host.OSName),
		Arch:            runtime.GOARCH,
		AgentVersion:    version,
	})
	if errors.Is(err, client.ErrUnauthorized) {
		return errors.New("enrollment token is invalid, expired, revoked or used up")
	}
	if err != nil {
		return err
	}
	cfg := protocol.ClampConfig(res.Config)
	if err := config.Save(f.configPath, &config.File{
		Server: strings.TrimRight(f.server, "/"), AgentID: res.AgentID, AgentSecret: res.AgentSecret,
		InsecureDev: f.insecureDev, ReportIntervalSec: cfg.ReportIntervalSec, SampleIntervalSec: cfg.SampleIntervalSec,
	}); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("Enrolled %s as agent %s. Config: %s\n", host.Hostname, res.AgentID, f.configPath)
	return nil
}

func cmdRun(args []string) error {
	f, err := parse("run", args, func(fs *flag.FlagSet, f *commonFlags) {
		fs.BoolVar(&f.once, "once", false, "send a single report and exit")
		fs.DurationVar(&f.window, "window", 10*time.Second, "sampling window for --once")
	})
	if err != nil {
		return err
	}
	cfg, err := config.Load(f.configPath)
	if err != nil {
		return err
	}
	opts := runner.Options{ConfigPath: f.configPath, Version: version, Once: f.once, Window: f.window}

	if !service.Interactive() {
		return runAsService(cfg, opts)
	}
	ctx, cancel := signalContext()
	defer cancel()
	err = runner.Run(ctx, cfg, opts, logger(os.Stderr))
	if errors.Is(err, client.ErrUnauthorized) {
		return errors.New("the server rejected this agent's credential (revoked?). Re-enroll with a new token")
	}
	return err
}

func cmdInstall(args []string) error {
	f, err := parse("install", args, enrollFlags)
	if err != nil {
		return err
	}
	if f.token != "" {
		if err := enroll(f); err != nil {
			return err
		}
	} else if _, err := config.Load(f.configPath); err != nil {
		return err
	}
	s, err := newService(f.configPath, nil)
	if err != nil {
		return err
	}
	if err := s.Install(); err != nil {
		return fmt.Errorf("install service (run as administrator/root): %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Println("Service installed and started:", serviceName)
	return nil
}

func cmdUninstall(args []string) error {
	f, err := parse("uninstall", args, func(fs *flag.FlagSet, f *commonFlags) {
		fs.BoolVar(&f.keepConfig, "keep-config", false, "keep the config file (and credential)")
	})
	if err != nil {
		return err
	}
	s, err := newService(f.configPath, nil)
	if err != nil {
		return err
	}
	_ = s.Stop()
	if err := s.Uninstall(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: uninstall service:", err)
	}
	if !f.keepConfig {
		if err := config.Remove(f.configPath); err != nil {
			return err
		}
	}
	fmt.Println("Removed. Revoke the agent in Settings › Agents if it will not come back.")
	return nil
}

func cmdStatus(args []string) error {
	f, err := parse("status", args, nil)
	if err != nil {
		return err
	}
	fmt.Printf("inframole-agent %s\nconfig: %s\n", version, f.configPath)
	if cfg, err := config.Load(f.configPath); err != nil {
		fmt.Println("enrolled: no —", err)
	} else {
		prefix := cfg.AgentSecret
		if len(prefix) > 12 {
			prefix = prefix[:12] + "…"
		}
		fmt.Printf("enrolled: yes\nserver: %s\nagent id: %s\ncredential: %s\n", cfg.Server, cfg.AgentID, prefix)
	}
	if s, err := newService(f.configPath, nil); err == nil {
		st, err := s.Status()
		switch {
		case err != nil:
			fmt.Println("service: not installed")
		case st == service.StatusRunning:
			fmt.Println("service: running")
		default:
			fmt.Println("service: stopped")
		}
	}
	return nil
}

// ───────────────────────── OS service ─────────────────────────

type program struct {
	cfg    *config.File
	opts   runner.Options
	cancel context.CancelFunc
	done   chan struct{}
	log    *slog.Logger
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		defer close(p.done)
		err := runner.Run(ctx, p.cfg, p.opts, p.log)
		if errors.Is(err, runner.ErrRestart) {
			// Exit non-zero: the service manager starts the new (or restored) binary.
			p.log.Info("exiting so the service manager restarts the agent")
			os.Exit(1)
		}
		if errors.Is(err, client.ErrUnauthorized) {
			// Stay up but idle: exiting would make the service manager restart us in a loop.
			p.log.Error("credential rejected by the server (agent revoked?). Idle until re-enrolled and restarted.")
			<-ctx.Done()
		} else if err != nil {
			p.log.Error("agent stopped", "err", err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

func newService(configPath string, prg *program) (service.Service, error) {
	if prg == nil {
		prg = &program{}
	}
	return service.New(prg, &service.Config{
		Name:        serviceName,
		DisplayName: "InfraMole Agent",
		Description: "Read-only discovery agent for InfraMole: reports host facts, running services, listening ports and TCP connections. No remote commands.",
		Arguments:   []string{"run", "--config", configPath},
		// Windows: restart when the process exits after a self-update (M22).
		// systemd units already have Restart=always.
		Option: service.KeyValue{"OnFailure": "restart", "OnFailureDelayDuration": "10s"},
	})
}

func runAsService(cfg *config.File, opts runner.Options) error {
	prg := &program{cfg: cfg, opts: opts}
	s, err := newService(opts.ConfigPath, prg)
	if err != nil {
		return err
	}
	svcLog, err := s.Logger(nil)
	if err != nil {
		return err
	}
	prg.log = logger(serviceWriter{svcLog})
	return s.Run()
}

// serviceWriter forwards slog lines to the OS service log (Event Log / journal).
type serviceWriter struct{ l service.Logger }

func (w serviceWriter) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	switch {
	case strings.Contains(line, "level=ERROR"):
		_ = w.l.Error(line)
	case strings.Contains(line, "level=WARN"):
		_ = w.l.Warning(line)
	default:
		_ = w.l.Info(line)
	}
	return len(p), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// cmdUpdate installs the newest signed release now (M22). Like the automatic
// check, it only trusts manifests signed with the compiled-in key.
func cmdUpdate(args []string) error {
	f, err := parse("update", args, func(fs *flag.FlagSet, f *commonFlags) {
		fs.BoolVar(&f.check, "check", false, "only report whether a newer release exists")
	})
	if err != nil {
		return err
	}
	baseURL := ""
	if cfg, err := config.Read(f.configPath); err == nil {
		baseURL = cfg.UpdateBaseURL
	}
	u, err := update.New(baseURL, version)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	plan, err := u.Check(ctx)
	if err != nil {
		return err
	}
	if plan == nil {
		fmt.Printf("inframole-agent %s is up to date.\n", version)
		return nil
	}
	if f.check {
		fmt.Printf("Update available: %s → %s (run: inframole-agent update)\n", version, plan.Version)
		return nil
	}
	if err := u.Apply(ctx, plan); err != nil {
		return err
	}
	fmt.Printf("Installed %s (the previous binary is kept until the new one reports).\n", plan.Version)
	if s, err := newService(f.configPath, nil); err == nil {
		if st, err := s.Status(); err == nil && st == service.StatusRunning {
			if err := s.Restart(); err != nil {
				return fmt.Errorf("restart the service to use the new version: %w", err)
			}
			fmt.Println("Service restarted.")
		}
	}
	return nil
}
