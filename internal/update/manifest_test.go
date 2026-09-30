// SPDX-License-Identifier: AGPL-3.0-only
package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

const manifestJSON = `{"files":{"inframole-agent_linux_amd64":"` +
	`0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},"version":"0.4.0"}`

func TestVerifyManifest(t *testing.T) {
	pub, priv := testKey(t)
	other, _ := testKey(t)
	data := []byte(manifestJSON)
	sig := ed25519.Sign(priv, data)

	m, err := VerifyManifest(data, sig, []ed25519.PublicKey{other, pub}) // any trusted key
	if err != nil || m.Version != "0.4.0" || len(m.Files) != 1 {
		t.Fatalf("m=%+v err=%v", m, err)
	}
	if _, err := VerifyManifest(data, sig, []ed25519.PublicKey{other}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("untrusted key accepted: %v", err)
	}
	tampered := []byte(manifestJSON[:len(manifestJSON)-4] + `5.0"}`)
	if _, err := VerifyManifest(tampered, sig, []ed25519.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered manifest accepted: %v", err)
	}
	if _, err := VerifyManifest(data, nil, []ed25519.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatal("missing signature accepted")
	}
	bad := []byte(`{"version":"0.4","files":{}}`)
	if _, err := VerifyManifest(bad, ed25519.Sign(priv, bad), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("invalid version accepted")
	}
	evil := []byte(`{"version":"0.4.0","files":{"../../etc/passwd":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`)
	if _, err := VerifyManifest(evil, ed25519.Sign(priv, evil), []ed25519.PublicKey{pub}); err == nil {
		t.Fatal("unexpected asset name accepted")
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
	}{
		{"0.4.0", "0.3.0", true},
		{"0.3.1", "0.3.0", true},
		{"1.0.0", "0.9.9", true},
		{"0.10.0", "0.9.0", true},
		{"0.3.0", "0.3.0", false},
		{"0.2.9", "0.3.0", false}, // never downgrade
		{"0.4.0", "0.3.0-dev", false},
		{"v0.4.0", "0.3.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.candidate, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.candidate, c.current, got)
		}
	}
}

func TestAssetName(t *testing.T) {
	if AssetName("windows", "amd64") != "inframole-agent_windows_amd64.exe" || AssetName("linux", "arm64") != "inframole-agent_linux_arm64" {
		t.Fatal("asset names")
	}
}
