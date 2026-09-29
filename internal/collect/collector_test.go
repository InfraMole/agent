// SPDX-License-Identifier: AGPL-3.0-only
package collect

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

func TestAssembleNeverEmitsNull(t *testing.T) {
	now := time.Now().UTC()
	r := Assemble("0.1.0", now, now, protocol.Host{OS: "linux"}, nil, nil, nil, nil, false)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "null") {
		t.Fatalf("report contains null: %s", b)
	}
	if r.Host.Hostname != "unknown" || r.Host.OSName != "linux" {
		t.Fatalf("host defaults not applied: %+v", r.Host)
	}
}

func TestAssembleTruncates(t *testing.T) {
	services := make([]protocol.Service, protocol.MaxServices+5)
	now := time.Now().UTC()
	r := Assemble("0.1.0", now, now, protocol.Host{Hostname: "h", OS: "linux"}, nil, services, nil, nil, false)
	if len(r.Services) != protocol.MaxServices || !r.Truncated {
		t.Fatalf("not truncated: %d %v", len(r.Services), r.Truncated)
	}
}

func TestParseSystemctl(t *testing.T) {
	out := `cron.service              loaded active running Regular background program processing daemon
nginx.service             loaded active running A high performance web server
not-a-service.socket      loaded active running socket
garbage
`
	got := parseSystemctl(out)
	if len(got) != 2 || got[0].Name != "cron" || got[1].Name != "nginx" ||
		got[1].State != "running" || got[1].DisplayName != "A high performance web server" {
		t.Fatalf("unexpected: %+v", got)
	}
}
