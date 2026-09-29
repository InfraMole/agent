#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Builds the release binaries and SHA256SUMS into agent/dist (docs/AGENT.md §10).
#   VERSION=0.2.0 ./scripts/release.sh
# Asset names carry no version so ".../releases/latest/download/<asset>" works;
# the version is embedded (inframole-agent version).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:?set VERSION, e.g. VERSION=0.2.0}"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "VERSION must be semver (got '$VERSION')" >&2
  exit 1
fi

rm -rf dist && mkdir -p dist
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  os=${target%/*} arch=${target#*/}
  ext=""; [[ $os == windows ]] && ext=".exe"
  out="dist/inframole-agent_${os}_${arch}${ext}"
  # Reproducible: no local paths, no build IDs, no cgo.
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o "$out" ./cmd/inframole-agent
  echo "built $out"
done
