// SPDX-License-Identifier: AGPL-3.0-only
package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// trustedKeys are the Ed25519 public keys whose signature on a release
// manifest the agent accepts (base64 of the raw 32 bytes). The matching
// private key signs manifest.json in the release workflow and never leaves
// GitHub's secret store (and the maintainer's offline backup). Rotating the
// key: add the new one here, ship a release signed with the old key, then
// sign with the new one and drop the old one in a later release.
var trustedKeys = []string{
	"/985phOmIg80CJtnG6ZDMw4GV5q4zUgLPfLwspEnvHU=", // 2026-09-30, AGENT_UPDATE_SIGNING_KEY
}

// TrustedKeys decodes the compiled-in keys (invalid entries are ignored).
func TrustedKeys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, k := range trustedKeys {
		b, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(b) == ed25519.PublicKeySize {
			out = append(out, ed25519.PublicKey(b))
		}
	}
	return out
}
