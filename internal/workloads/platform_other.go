// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package workloads

import (
	"context"

	"github.com/InfraMole/agent/internal/protocol"
)

// Supported: workloads are Windows-only for now (IIS, SQL Server).
const Supported = false

func iisSites() ([]protocol.IISSite, bool, error) { return nil, false, nil }

func sqlDatabases(context.Context) ([]protocol.SQLDatabase, error) { return nil, nil }
