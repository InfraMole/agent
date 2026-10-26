// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestSiteResolver(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	calls := 0
	workers := map[int32]string{100: "BillingPool", 200: "SharedPool"}
	var fail error
	r := &siteResolver{
		now: func() time.Time { return now },
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		list: func() (map[int32]string, map[string][]string, error) {
			calls++
			return workers, map[string][]string{"billingpool": {"Billing"}, "sharedpool": {"A", "B"}}, fail
		},
	}
	if got := r.resolve(100, "sqlservr.exe"); got != "" || calls != 0 {
		t.Fatalf("non-worker processes are never listed: %q, %d calls", got, calls)
	}
	if got := r.resolve(100, "W3WP.EXE"); got != "Billing" || calls != 1 {
		t.Fatalf("first worker: %q, %d calls", got, calls)
	}
	if r.resolve(200, "w3wp.exe") != "" || r.resolve(100, "w3wp.exe") != "Billing" || calls != 1 {
		t.Fatalf("known workers come from the cache (%d calls)", calls)
	}
	// A new worker shortly after: not listed again until refreshGap.
	workers[300] = "BillingPool"
	if r.resolve(300, "w3wp.exe") != "" || calls != 1 {
		t.Fatal("refresh is throttled")
	}
	now = now.Add(refreshGap)
	if r.resolve(300, "w3wp.exe") != "Billing" || calls != 2 {
		t.Fatalf("new worker after the gap (%d calls)", calls)
	}
	// An unknown id is remembered as "no site".
	now = now.Add(refreshGap)
	if r.resolve(999, "w3wp.exe") != "" || calls != 3 {
		t.Fatal("unknown worker")
	}
	now = now.Add(refreshGap)
	if r.resolve(999, "w3wp.exe") != "" || calls != 3 {
		t.Fatal("an unknown worker does not trigger another listing")
	}
	// Periodic refresh; a failing listing keeps the last answer.
	now = now.Add(refreshEvery)
	fail = errors.New("appcmd failed")
	if r.resolve(100, "w3wp.exe") != "Billing" || calls != 4 {
		t.Fatalf("failed refresh keeps the cache (%d calls)", calls)
	}
}
