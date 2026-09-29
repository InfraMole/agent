// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/InfraMole/agent/internal/protocol"
)

// Everything in this file is READ-ONLY: it only queries OS tables. No files
// are read, no commands with user input are executed, no process arguments
// or environment variables are collected (docs/AGENT.md §3).

// HostInfo returns host facts plus the stable machine id used for enrollment.
func HostInfo(ctx context.Context) (protocol.Host, string, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return protocol.Host{}, "", err
	}
	h := protocol.Host{
		Hostname:      info.Hostname,
		FQDN:          fqdn(info.Hostname),
		OS:            runtime.GOOS,
		OSName:        truncate(strings.TrimSpace(info.Platform), 128),
		OSVersion:     truncate(strings.TrimSpace(info.PlatformVersion), 128),
		KernelVersion: truncate(info.KernelVersion, 128),
		Arch:          runtime.GOARCH,
	}
	if h.OSName == "" {
		h.OSName = runtime.GOOS
	}
	if info.BootTime > 0 {
		boot := time.Unix(int64(info.BootTime), 0).UTC()
		h.BootTime = &boot
	}
	return h, info.HostID, nil
}

// Interfaces returns interfaces with at least one address (loopback skipped).
func Interfaces(ctx context.Context) ([]protocol.Interface, error) {
	stats, err := gnet.InterfacesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := []protocol.Interface{}
	for _, s := range stats {
		if hasFlag(s.Flags, "loopback") || len(s.Addrs) == 0 {
			continue
		}
		iface := protocol.Interface{Name: truncate(s.Name, 128), MAC: s.HardwareAddr, Addresses: []string{}}
		for _, a := range s.Addrs {
			if len(iface.Addresses) >= protocol.MaxAddresses {
				break
			}
			iface.Addresses = append(iface.Addresses, a.Addr)
		}
		out = append(out, iface)
		if len(out) >= protocol.MaxInterfaces {
			break
		}
	}
	return out, nil
}

// Sockets returns the TCP table (IPv4 + IPv6) with owning PIDs.
func Sockets(ctx context.Context) ([]Socket, error) {
	conns, err := gnet.ConnectionsWithContext(ctx, "tcp")
	if err != nil {
		return nil, err
	}
	out := make([]Socket, 0, len(conns))
	for _, c := range conns {
		out = append(out, Socket{
			LocalIP: c.Laddr.IP, LocalPort: c.Laddr.Port,
			RemoteIP: c.Raddr.IP, RemotePort: c.Raddr.Port,
			Status: c.Status, PID: c.Pid,
		})
	}
	return out, nil
}

// NewProcessResolver returns a resolver that caches name + executable path
// per PID for the lifetime of one sample. It never reads command lines.
func NewProcessResolver(ctx context.Context) ProcessResolver {
	cache := map[int32]*protocol.ProcessRef{}
	return func(pid int32) *protocol.ProcessRef {
		if pid <= 0 {
			return nil
		}
		if ref, ok := cache[pid]; ok {
			return ref
		}
		var ref *protocol.ProcessRef
		if p, err := process.NewProcessWithContext(ctx, pid); err == nil {
			if name, err := p.NameWithContext(ctx); err == nil && name != "" {
				ref = &protocol.ProcessRef{Name: truncate(name, protocol.MaxShortStringLen), PID: pid}
				if exe, err := p.ExeWithContext(ctx); err == nil {
					ref.Path = truncate(exe, protocol.MaxProcessPathLen)
				}
			}
		}
		cache[pid] = ref
		return ref
	}
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
