// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/client"
	"github.com/InfraMole/agent/internal/collect"
	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

// M39: a failed report's connections go with the next one, and collection
// issues are sent only once the server has listed "collection-issues".
func TestSendKeepsFailedWindowAndNegotiatesIssues(t *testing.T) {
	var bodies []map[string]json.RawMessage
	status := []int{http.StatusServiceUnavailable, http.StatusAccepted, http.StatusAccepted}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		w.WriteHeader(status[len(bodies)-1])
		_, _ = w.Write([]byte(`{"config":{"reportIntervalSec":300,"sampleIntervalSec":30},"features":["collection-issues"]}`))
	}))
	defer srv.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := client.New(srv.URL, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.File{Server: srv.URL, AgentSecret: "s"}
	col := collect.NewCollector("test", log)
	t0 := time.Now().UTC().Add(-10 * time.Minute)
	col.Restore(protocol.Report{WindowStart: t0, Connections: []protocol.Connection{
		{Proto: "tcp", Direction: "outbound", RemoteAddress: "10.0.0.40", RemotePort: 1433, Count: 4, FirstSeen: t0, LastSeen: t0},
	}})
	inv := &Inventory{log: log}
	inv.issues.Record(protocol.CollectorProxmox, errors.New("boom"))
	wl := &serverWorkloads{}
	sf := &serverFeatures{}
	ctx := context.Background()

	if _, err := send(ctx, c, cfg, col, inv, wl, sf, log); err == nil {
		t.Fatal("first report should fail (503)")
	}
	if _, err := send(ctx, c, cfg, col, inv, wl, sf, log); err != nil {
		t.Fatal(err)
	}
	if _, err := send(ctx, c, cfg, col, inv, wl, sf, log); err != nil {
		t.Fatal(err)
	}

	var second []protocol.Connection
	_ = json.Unmarshal(bodies[1]["connections"], &second)
	found := false
	for _, conn := range second {
		if conn.RemoteAddress == "10.0.0.40" && conn.Count == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the failed report's connection was lost: %s", bodies[1]["connections"])
	}
	if _, ok := bodies[1]["issues"]; ok {
		t.Fatal("issues sent before the server listed the feature")
	}
	if _, ok := bodies[1]["dnsServers"]; ok {
		t.Fatal("DNS servers sent before the server listed the feature")
	}
	var issues []protocol.Issue
	if err := json.Unmarshal(bodies[2]["issues"], &issues); err != nil {
		t.Fatalf("issues missing after negotiation: %v", err)
	}
	proxmox := false
	for _, i := range issues {
		if i.Collector == protocol.CollectorProxmox && i.Error == protocol.IssueFailed {
			proxmox = true
		}
	}
	if !proxmox {
		t.Fatalf("proxmox issue not reported: %+v", issues)
	}
}
