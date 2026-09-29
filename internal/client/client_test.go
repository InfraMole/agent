// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/InfraMole/agent/internal/protocol"
)

func TestRequiresHTTPS(t *testing.T) {
	if _, err := New("http://example.com", false, "t"); err == nil {
		t.Fatal("plain http accepted without --insecure-dev")
	}
	if _, err := New("https://example.com", false, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := New("http://localhost:3000", true, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := New("not a url", true, "t"); err == nil {
		t.Fatal("invalid URL accepted")
	}
}

func TestReportSendsBearerAndClampsConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/report" || r.Header.Get("Authorization") != "Bearer secret" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad request: %s %v", r.URL.Path, r.Header)
		}
		var rep protocol.Report
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil || rep.SchemaVersion != 1 {
			t.Errorf("bad body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"config":{"reportIntervalSec":5,"sampleIntervalSec":30}}`))
	}))
	defer srv.Close()

	c, _ := New(srv.URL, true, "test")
	cfg, err := c.Report(context.Background(), "secret", protocol.Report{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ReportIntervalSec != protocol.MinReportInterval {
		t.Fatalf("server config not clamped: %+v", cfg)
	}
}

func TestErrorMapping(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, true, "test")

	if _, err := c.Report(context.Background(), "s", protocol.Report{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	status = http.StatusTooManyRequests
	_, err := c.Report(context.Background(), "s", protocol.Report{})
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Fatalf("want RateLimitedError(7s), got %v", err)
	}
	status = http.StatusUnprocessableEntity
	if _, err := c.Report(context.Background(), "s", protocol.Report{}); err == nil {
		t.Fatal("422 not reported as error")
	}
}

func TestRefusesRedirects(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked = true
		}
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c, _ := New(srv.URL, true, "test")
	if _, err := c.Report(context.Background(), "secret", protocol.Report{}); err == nil {
		t.Fatal("redirect response should be an error")
	}
	if leaked {
		t.Fatal("bearer secret was sent to the redirect target")
	}
}

func TestServerMessageIsShown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"error":"plan_limit","message":"This installation is on 25 of 25 billable nodes."}`))
	}))
	defer srv.Close()
	c, err := New(srv.URL, true, "t")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Enroll(context.Background(), protocol.EnrollRequest{})
	if err == nil || err.Error() != "server returned 402: This installation is on 25 of 25 billable nodes." {
		t.Fatalf("got %v", err)
	}
}
