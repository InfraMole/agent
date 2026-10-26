// SPDX-License-Identifier: AGPL-3.0-only
package runner

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/client"
	"github.com/InfraMole/agent/internal/collect"
	"github.com/InfraMole/agent/internal/config"
	"github.com/InfraMole/agent/internal/protocol"
)

// M42: the site of a connection goes only to a server that lists
// "connection-sites"; a server that rejects it stops getting it.
func TestSendNegotiatesConnectionSites(t *testing.T) {
	var bodies []string
	features := `["connection-sites"]`
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"config":{"reportIntervalSec":300,"sampleIntervalSec":30},"features":` + features + `}`))
	}))
	defer srv.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := client.New(srv.URL, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.File{Server: srv.URL, AgentSecret: "s"}
	col := collect.NewCollector("test", log)
	withSite := func() {
		t0 := time.Now().UTC()
		col.Restore(protocol.Report{WindowStart: t0, Connections: []protocol.Connection{
			{Proto: "tcp", Direction: "outbound", RemoteAddress: "10.0.0.40", RemotePort: 1433, Site: "Billing", Count: 2, FirstSeen: t0, LastSeen: t0},
		}})
	}
	wl, sf, ctx := &serverWorkloads{}, &serverFeatures{}, context.Background()

	withSite()
	if _, err := send(ctx, c, cfg, col, nil, wl, sf, log); err != nil {
		t.Fatal(err)
	}
	withSite()
	if _, err := send(ctx, c, cfg, col, nil, wl, sf, log); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(bodies[0], `"site"`) || !strings.Contains(bodies[1], `"site":"Billing"`) {
		t.Fatalf("site before / after negotiation:\n%s\n%s", bodies[0], bodies[1])
	}
	if strings.Contains(bodies[1], "databaseClients") {
		t.Fatal("database clients were not negotiated")
	}

	status = http.StatusUnprocessableEntity
	withSite()
	_, _ = send(ctx, c, cfg, col, nil, wl, sf, log)
	status = http.StatusAccepted
	withSite()
	if _, err := send(ctx, c, cfg, col, nil, wl, sf, log); err != nil {
		t.Fatal(err)
	}
	var last struct{ Connections []protocol.Connection }
	_ = json.Unmarshal([]byte(bodies[3]), &last)
	if !sf.sitesDisabled || strings.Contains(bodies[3], `"site"`) || len(last.Connections) == 0 {
		t.Fatalf("after a rejection the site is no longer sent: %s", bodies[3])
	}
}
