// SPDX-License-Identifier: AGPL-3.0-only
package workloads

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// An empty collection is "none", not "not collected": it must encode as [],
// never null (the server's schema rejects null).
func TestEmptyCollectionsEncodeAsArrays(t *testing.T) {
	c := &Collector{sql: true, interval: time.Hour, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w := c.Due(context.Background(), time.Now())
	if !Supported {
		// Off Windows sqlDatabases() returns nil, nil: still an empty snapshot.
		if w == nil || w.SQLDatabases == nil {
			t.Fatalf("expected an empty SQL snapshot, got %+v", w)
		}
	}
	if w == nil {
		t.Skip("no SQL snapshot on this machine")
	}
	b, _ := json.Marshal(w)
	if strings.Contains(string(b), "null") {
		t.Fatalf("encoded null: %s", b)
	}
	if c.Due(context.Background(), time.Now()) != nil {
		t.Fatal("must wait for the interval before collecting again")
	}
}
