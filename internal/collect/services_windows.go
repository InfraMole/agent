// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package collect

import (
	"context"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/InfraMole/agent/internal/protocol"
)

// Services lists RUNNING Win32 services via the Service Control Manager with
// the minimum access rights (enumerate + query config), so it also works for
// non-administrators.
func Services(_ context.Context) ([]protocol.Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(scm)

	var needed, count, resume uint32
	var buf []byte
	size := uint32(64 * 1024)
	for {
		buf = make([]byte, size)
		err = windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_ACTIVE, &buf[0], size, &needed, &count, &resume, nil)
		if err == windows.ERROR_MORE_DATA && needed > size {
			size = needed
			resume = 0
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}

	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
	out := make([]protocol.Service, 0, len(entries))
	for _, e := range entries {
		name := windows.UTF16PtrToString(e.ServiceName)
		svc := protocol.Service{
			Name:        truncate(name, protocol.MaxShortStringLen),
			DisplayName: truncate(windows.UTF16PtrToString(e.DisplayName), protocol.MaxShortStringLen),
			State:       stateName(e.ServiceStatusProcess.CurrentState),
			StartType:   startType(scm, name),
		}
		out = append(out, svc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > protocol.MaxServices {
		out = out[:protocol.MaxServices]
	}
	return out, nil
}

func startType(scm windows.Handle, name string) string {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	h, err := windows.OpenService(scm, ptr, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return ""
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return ""
	}
	switch cfg.StartType {
	case mgr.StartAutomatic:
		if cfg.DelayedAutoStart {
			return "auto-delayed"
		}
		return "auto"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	default:
		return ""
	}
}

func stateName(state uint32) string {
	switch state {
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return "other"
	}
}
