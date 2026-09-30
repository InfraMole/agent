// SPDX-License-Identifier: AGPL-3.0-only
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// releaseServer serves a signed manifest and the binary for this platform.
func releaseServer(t *testing.T, priv ed25519.PrivateKey, version string, binary []byte, tamper bool) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(binary)
	m, _ := json.Marshal(Manifest{Version: version, Files: map[string]string{
		AssetName(runtime.GOOS, runtime.GOARCH): hex.EncodeToString(sum[:]),
	}})
	sig := ed25519.Sign(priv, m)
	served := binary
	if tamper {
		served = append([]byte("evil"), binary...)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(m) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sig) })
	mux.HandleFunc("/"+AssetName(runtime.GOOS, runtime.GOARCH), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(served)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func updater(t *testing.T, srv *httptest.Server, pub ed25519.PublicKey, current string) *Updater {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "inframole-agent")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{
		BaseURL: srv.URL,
		Current: current,
		Keys:    []ed25519.PublicKey{pub},
		Exe:     exe,
		HTTP:    srv.Client(),
		Probe:   func(context.Context, string, string) error { return nil },
	}
}

func TestCheckAndApply(t *testing.T) {
	pub, priv := testKey(t)
	srv := releaseServer(t, priv, "0.4.0", []byte("new binary"), false)
	u := updater(t, srv, pub, "0.3.0")

	plan, err := u.Check(context.Background())
	if err != nil || plan == nil || plan.Version != "0.4.0" {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if err := u.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(u.Exe); string(b) != "new binary" {
		t.Fatalf("binary not replaced: %q", b)
	}
	if b, _ := os.ReadFile(u.Exe + ".previous"); string(b) != "old binary" {
		t.Fatalf("previous not kept: %q", b)
	}
	Confirm(u.Exe) // first successful report
	for _, leftover := range []string{".previous", ".update.json"} {
		if _, err := os.Stat(u.Exe + leftover); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left behind", leftover)
		}
	}
}

func TestNoUpdateWhenCurrentOrUntrusted(t *testing.T) {
	pub, priv := testKey(t)
	other, _ := testKey(t)
	srv := releaseServer(t, priv, "0.3.0", []byte("same"), false)
	if plan, err := updater(t, srv, pub, "0.3.0").Check(context.Background()); plan != nil || err != nil {
		t.Fatalf("same version: plan=%+v err=%v", plan, err)
	}
	if plan, err := updater(t, srv, pub, "0.4.0").Check(context.Background()); plan != nil || err != nil {
		t.Fatalf("older release: plan=%+v err=%v", plan, err)
	}
	if _, err := updater(t, srv, other, "0.2.0").Check(context.Background()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("untrusted signature: %v", err)
	}
}

func TestTamperedBinaryIsRejected(t *testing.T) {
	pub, priv := testKey(t)
	srv := releaseServer(t, priv, "0.4.0", []byte("new binary"), true)
	u := updater(t, srv, pub, "0.3.0")
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered binary: %v", err)
	}
	if b, _ := os.ReadFile(u.Exe); string(b) != "old binary" {
		t.Fatal("current binary must stay untouched")
	}
}

func TestProbeFailureKeepsCurrentBinary(t *testing.T) {
	pub, priv := testKey(t)
	srv := releaseServer(t, priv, "0.4.0", []byte("new binary"), false)
	u := updater(t, srv, pub, "0.3.0")
	u.Probe = func(context.Context, string, string) error { return errors.New("exec format error") }
	plan, _ := u.Check(context.Background())
	if err := u.Apply(context.Background(), plan); err == nil {
		t.Fatal("a binary that does not run must not be installed")
	}
	if b, _ := os.ReadFile(u.Exe); string(b) != "old binary" {
		t.Fatal("current binary must stay untouched")
	}
}

func TestRollbackAfterRepeatedFailedStarts(t *testing.T) {
	pub, priv := testKey(t)
	srv := releaseServer(t, priv, "0.4.0", []byte("new binary"), false)
	u := updater(t, srv, pub, "0.3.0")
	plan, _ := u.Check(context.Background())
	if err := u.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxAttempts; i++ {
		if rolled, err := OnStart(u.Exe); rolled || err != nil {
			t.Fatalf("start %d: rolled=%v err=%v", i, rolled, err)
		}
	}
	rolled, err := OnStart(u.Exe) // never confirmed: give up on the new version
	if !rolled || err != nil {
		t.Fatalf("rolled=%v err=%v", rolled, err)
	}
	if b, _ := os.ReadFile(u.Exe); string(b) != "old binary" {
		t.Fatalf("previous not restored: %q", b)
	}
	if rolled, _ := OnStart(u.Exe); rolled {
		t.Fatal("state must be cleared after a rollback")
	}
}
