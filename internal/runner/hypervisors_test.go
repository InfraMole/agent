// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

func TestHypervisorsNegotiatedAndPaced(t *testing.T) {
	calls := 0
	inv := &Inventory{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		hypervisors: []*hypervisorCollector{{
			source: "vcenter", interval: time.Hour,
			collect: func(context.Context) (*protocol.Hypervisor, error) {
				calls++
				return &protocol.Hypervisor{Source: "vcenter"}, nil
			},
		}},
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	if got := inv.DueHypervisors(ctx, now, false); got != nil || calls != 0 {
		t.Fatal("collected before the server accepted the section")
	}
	inv.negotiated([]string{"workloads", protocol.FeatureHypervisors})
	if got := inv.DueHypervisors(ctx, now, false); len(got) != 1 || calls != 1 {
		t.Fatalf("got %v, calls %d", got, calls)
	}
	if got := inv.DueHypervisors(ctx, now.Add(10*time.Minute), false); got != nil {
		t.Fatal("collected again before the interval")
	}
	inv.RetryHypervisors([]protocol.Hypervisor{{Source: "vcenter"}}) // report failed
	if got := inv.DueHypervisors(ctx, now.Add(11*time.Minute), false); len(got) != 1 {
		t.Fatal("not retried after a failed report")
	}
	inv.hvDisabled = true // server rejected it (422)
	if got := inv.DueHypervisors(ctx, now.Add(3*time.Hour), false); got != nil {
		t.Fatal("sent after a rejection")
	}
	if got := inv.DueHypervisors(ctx, now.Add(3*time.Hour), true); len(got) != 1 {
		t.Fatal("dry-run must always collect")
	}
	inv.negotiated(nil) // an older server
	if inv.hvAccepted {
		t.Fatal("still accepted")
	}
}
