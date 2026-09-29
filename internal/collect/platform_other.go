// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows && !linux

package collect

import (
	"context"

	"github.com/InfraMole/agent/internal/protocol"
)

// Services is unsupported on this platform (Windows and Linux only).
func Services(_ context.Context) ([]protocol.Service, error) { return []protocol.Service{}, nil }

func fqdn(hostname string) string { return fqdnFromDNS(hostname) }
