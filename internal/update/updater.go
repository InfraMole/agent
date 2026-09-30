// SPDX-License-Identifier: AGPL-3.0-only
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultBaseURL: the official releases. A mirror can be set locally
// (config "updateBaseUrl"); the server can never choose it.
const DefaultBaseURL = "https://github.com/InfraMole/agent/releases/latest/download"

const (
	maxManifestBytes = 64 << 10
	maxBinaryBytes   = 64 << 20
	// A new version that has not sent one report after this many starts is rolled back.
	maxAttempts = 3
)

// Updater checks for, verifies and installs a newer agent binary.
type Updater struct {
	BaseURL string
	Current string // running version
	Keys    []ed25519.PublicKey
	Exe     string // path of the running binary
	HTTP    *http.Client
	// Probe runs the downloaded binary ("<bin> version") before it replaces
	// the current one. Tests replace it.
	Probe func(ctx context.Context, path, version string) error
}

// Plan is a verified, newer release for this platform.
type Plan struct {
	Version string
	Asset   string
	SHA256  string
}

// New returns an updater for the running binary with the compiled-in keys.
func New(baseURL, current string) (*Updater, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Updater{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Current: current,
		Keys:    TrustedKeys(),
		Exe:     exe,
		HTTP:    &http.Client{Timeout: 5 * time.Minute, CheckRedirect: httpsOnly},
		Probe:   probe,
	}, nil
}

// Redirects are fine (GitHub serves assets from another host): integrity
// comes from the signature, not the transport. Downgrades to http are not.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
		return errors.New("refusing a redirect away from https")
	}
	return nil
}

// Check fetches and verifies the manifest. It returns nil when there is no
// newer release for this OS / architecture.
func (u *Updater) Check(ctx context.Context) (*Plan, error) {
	if len(u.Keys) == 0 {
		return nil, errors.New("this build has no update key: self-update is not available")
	}
	data, err := u.get(ctx, "manifest.json", maxManifestBytes)
	if err != nil {
		return nil, err
	}
	sig, err := u.get(ctx, "manifest.json.sig", 1024)
	if err != nil {
		return nil, err
	}
	m, err := VerifyManifest(data, sig, u.Keys)
	if err != nil {
		return nil, err
	}
	if !Newer(m.Version, u.Current) {
		return nil, nil
	}
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	sum, ok := m.Files[asset]
	if !ok {
		return nil, fmt.Errorf("release %s has no %s", m.Version, asset)
	}
	return &Plan{Version: m.Version, Asset: asset, SHA256: sum}, nil
}

// Apply downloads the planned binary, checks its hash and that it runs, keeps
// the current binary as <exe>.previous and puts the new one in its place.
// The caller then exits so the service manager starts the new version.
func (u *Updater) Apply(ctx context.Context, p *Plan) error {
	dir := filepath.Dir(u.Exe)
	tmp, err := os.CreateTemp(dir, ".inframole-agent-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed
	body, err := u.open(ctx, p.Asset)
	if err != nil {
		tmp.Close()
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, maxBinaryBytes+1))
	body.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxBinaryBytes {
		return errors.New("update binary is too large")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != p.SHA256 {
		return fmt.Errorf("update binary hash mismatch (got %s)", got)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	if err := u.Probe(ctx, tmpPath, p.Version); err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}

	previous := u.Exe + ".previous"
	_ = os.Remove(previous)
	if err := os.Rename(u.Exe, previous); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, u.Exe); err != nil {
		_ = os.Rename(previous, u.Exe) // put things back
		return err
	}
	return writeState(u.Exe, state{From: u.Current, To: p.Version})
}

// state tracks an update until the new version has proven itself.
type state struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Attempts int    `json:"attempts"`
}

func statePath(exe string) string { return exe + ".update.json" }

func writeState(exe string, s state) error {
	b, _ := json.Marshal(s)
	return os.WriteFile(statePath(exe), b, 0o600)
}

// OnStart must run when the agent starts. After an update it counts the
// start; once the new version has failed to report maxAttempts times it
// restores the previous binary and returns rolledBack=true (the caller exits
// so the service manager starts the old version again).
func OnStart(exe string) (rolledBack bool, err error) {
	b, err := os.ReadFile(statePath(exe))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var s state
	if json.Unmarshal(b, &s) != nil {
		_ = os.Remove(statePath(exe))
		return false, nil
	}
	s.Attempts++
	if s.Attempts <= maxAttempts {
		return false, writeState(exe, s)
	}
	previous := exe + ".previous"
	if _, err := os.Stat(previous); err != nil {
		_ = os.Remove(statePath(exe))
		return false, fmt.Errorf("update to %s kept failing and there is no previous binary to restore", s.To)
	}
	broken := exe + ".failed"
	_ = os.Remove(broken)
	if err := os.Rename(exe, broken); err != nil {
		return false, err
	}
	if err := os.Rename(previous, exe); err != nil {
		_ = os.Rename(broken, exe)
		return false, err
	}
	_ = os.Remove(statePath(exe))
	return true, nil
}

// Confirm runs after the first successful report: the update stays.
func Confirm(exe string) {
	if _, err := os.Stat(statePath(exe)); err == nil {
		_ = os.Remove(statePath(exe))
		_ = os.Remove(exe + ".previous")
		_ = os.Remove(exe + ".failed")
	}
}

func (u *Updater) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	body, err := u.open(ctx, name)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is too large", name)
	}
	return b, nil
}

func (u *Updater) open(ctx context.Context, name string) (io.ReadCloser, error) {
	target, err := url.JoinPath(u.BaseURL, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "inframole-agent/"+u.Current+" (update)")
	res, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", name, res.Status)
	}
	return res.Body, nil
}

// probe runs "<bin> version" and expects the planned version in its output.
func probe(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output() // fixed arguments, never server input
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), version) {
		return fmt.Errorf("it reports %q, expected %s", strings.TrimSpace(string(out)), version)
	}
	return nil
}
