// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"testing"
	"time"
)

func TestInventoryNilIsNoop(t *testing.T) {
	var inv *Inventory
	if got := inv.Due(context.Background(), time.Now()); got != nil {
		t.Fatalf("nil inventory returned %+v", got)
	}
	inv.Retry() // must not panic
}

func TestInventoryCadence(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	inv := &Inventory{interval: time.Hour, last: now}
	if inv.Due(context.Background(), now.Add(30*time.Minute)) != nil || !inv.last.Equal(now) {
		t.Fatal("collected before the interval elapsed")
	}
	inv.Retry()
	if !inv.last.IsZero() {
		t.Fatal("Retry should make the next report collect again")
	}
}
