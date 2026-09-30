// SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package update

import (
	"time"

	"golang.org/x/sys/windows/svc/mgr"
)

// EnsureServiceRestart makes the Service Control Manager restart the agent
// when its process exits after an update. Services installed before M22 had
// no recovery actions; this fixes them in place (the agent runs as
// LocalSystem). A no-op error when not running as that service.
func EnsureServiceRestart(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, uint32((24 * time.Hour).Seconds()))
}
