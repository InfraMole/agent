// SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package inventory

import (
	"context"
	"errors"

	"github.com/InfraMole/agent/internal/protocol"
)

// HyperV is Windows-only.
type HyperV struct{}

func NewHyperV() (*HyperV, error) { return nil, errors.New("hyperv: only available on Windows") }

func (HyperV) Collect(context.Context) (*protocol.Hypervisor, error) {
	return nil, errors.New("hyperv: only available on Windows")
}
