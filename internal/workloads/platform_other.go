// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows && !linux

package workloads

import (
	"context"

	"github.com/InfraMole/agent/internal/protocol"
)

// Supported: workloads exist on Windows (M16) and Linux (M20) only.
const (
	Supported = false
	onWindows = false
	onLinux   = false
)

func iisSites() ([]protocol.WebSite, bool, error)                          { return nil, false, nil }
func nginxSites() ([]protocol.WebSite, bool, error)                        { return nil, false, nil }
func apacheSites() ([]protocol.WebSite, bool, error)                       { return nil, false, nil }
func haproxySites() ([]protocol.WebSite, bool, error)                      { return nil, false, nil }
func sqlDatabases(context.Context) ([]protocol.Database, error)            { return nil, nil }
func postgresDatabases(context.Context) ([]protocol.Database, bool, error) { return nil, false, nil }
func mysqlDatabases(context.Context) ([]protocol.Database, bool, error)    { return nil, false, nil }
