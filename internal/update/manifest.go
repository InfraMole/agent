// SPDX-License-Identifier: AGPL-3.0-only
// Package update implements the agent's opt-in self-update (M22, ADR-033).
//
// Trust model: the InfraMole server has no say — there is still no command
// channel. The agent itself checks the official release location (or a
// mirror configured in its local config) for manifest.json, which lists the
// release version and the SHA-256 of every binary, signed with Ed25519. The
// signature must verify against a public key compiled into the agent
// (keys.go); the downloaded binary must match its hash; only newer versions
// are accepted.
package update

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Manifest is the signed description of one release.
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"` // asset name → lowercase hex SHA-256
}

var (
	ErrBadSignature = errors.New("update manifest signature does not verify against the agent's trusted keys")
	semverRe        = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	sha256Re        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// VerifyManifest checks the Ed25519 signature over the exact manifest bytes
// against any of the trusted keys, then parses and validates it.
func VerifyManifest(data, sig []byte, keys []ed25519.PublicKey) (*Manifest, error) {
	ok := false
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, data, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrBadSignature
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("update manifest: %w", err)
	}
	if !semverRe.MatchString(m.Version) {
		return nil, fmt.Errorf("update manifest: invalid version %q", m.Version)
	}
	for name, sum := range m.Files {
		if !strings.HasPrefix(name, "inframole-agent_") || !sha256Re.MatchString(sum) {
			return nil, fmt.Errorf("update manifest: invalid entry %q", name)
		}
	}
	return &m, nil
}

// Newer reports whether candidate is a strictly higher release than current.
// Development builds ("0.3.0-dev", anything that is not x.y.z) never update.
func Newer(candidate, current string) bool {
	c, ok1 := parse(candidate)
	cur, ok2 := parse(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range 3 {
		if c[i] != cur[i] {
			return c[i] > cur[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range 3 {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// AssetName is the release file for an OS / architecture, as built by
// scripts/release.sh ("inframole-agent_linux_amd64", "…_windows_arm64.exe").
func AssetName(goos, goarch string) string {
	name := "inframole-agent_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}
