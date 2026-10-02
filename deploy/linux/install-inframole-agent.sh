#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Installs and enrols the InfraMole agent on this Linux machine, once.
# Made for mass deployment (cloud-init, an RMM, a for-loop over ssh). Safe
# to run again:
#   - already installed and enrolled: makes sure the service runs, exits 0;
#   - enrolled but the service was removed: reinstalls it with the existing
#     credential (no new enrolment);
#   - otherwise: downloads the agent, verifies it against SHA256SUMS, enrols
#     it with the enrollment token and starts the service.
#
# Usage (as root):
#   INFRAMOLE_SERVER=https://inframole.example.com \
#   INFRAMOLE_ENROLLMENT_TOKEN=dmp_enr_... \
#   sh install-inframole-agent.sh
#
# Optional:
#   INFRAMOLE_DOWNLOAD_BASE_URL  where the binaries and SHA256SUMS are
#                                (default: the latest public release)
#   INFRAMOLE_INSECURE_DEV=1     allow an http:// server (local tests only)
#
# Guide: https://inframole.com/docs/agent/mass-deployment
set -eu

SERVER="${INFRAMOLE_SERVER:-}"
BASE="${INFRAMOLE_DOWNLOAD_BASE_URL:-https://github.com/InfraMole/agent/releases/latest/download}"
BIN=/usr/local/bin/inframole-agent
CONFIG=/etc/inframole/agent.json
SERVICE=inframole-agent

log() { echo "inframole-deploy: $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

service_installed() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files "$SERVICE.service" 2>/dev/null | grep -q "^$SERVICE.service"
  else
    [ -e "/etc/init.d/$SERVICE" ]
  fi
}
service_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet "$SERVICE"
  else
    "/etc/init.d/$SERVICE" status >/dev/null 2>&1
  fi
}
service_start() {
  if command -v systemctl >/dev/null 2>&1; then systemctl start "$SERVICE"; else "/etc/init.d/$SERVICE" start; fi
}

# 1. Already done: keep the service running and stop here.
if [ -x "$BIN" ] && [ -f "$CONFIG" ] && service_installed; then
  if ! service_running; then
    service_start
    log "service was stopped; started"
  fi
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -n "$SERVER" ] || die "set INFRAMOLE_SERVER"
FLAGS="--server $SERVER"
if [ "${INFRAMOLE_INSECURE_DEV:-}" = "1" ]; then
  FLAGS="$FLAGS --insecure-dev"
else
  case "$SERVER" in https://*) ;; *) die "the server must use https://" ;; esac
fi

# 2. The binary, verified against SHA256SUMS before it is ever run.
if [ ! -x "$BIN" ]; then
  case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
  FILE="inframole-agent_linux_$ARCH"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  for name in "$FILE" SHA256SUMS; do
    case "$BASE" in
      http://* | https://*) curl -fsSL --retry 3 -o "$TMP/$name" "$BASE/$name" ;;
      *) cp "$BASE/$name" "$TMP/$name" ;;
    esac
  done
  (cd "$TMP" && grep -E " \*?$FILE\$" SHA256SUMS | sha256sum -c -) >/dev/null ||
    die "checksum mismatch for $FILE - not installing it"
  install -m 0755 "$TMP/$FILE" "$BIN"
  log "installed $FILE from $BASE"
fi

# 3. Enrolled before (the service was removed): reuse the credential.
if [ -f "$CONFIG" ]; then
  # shellcheck disable=SC2086 # FLAGS is a list of words
  env -u INFRAMOLE_ENROLLMENT_TOKEN "$BIN" install $FLAGS
  log "service reinstalled with the existing enrolment"
  exit 0
fi

# 4. First time: enrol and start the service. The token stays in the
#    environment, never on a command line other users can read.
[ -n "${INFRAMOLE_ENROLLMENT_TOKEN:-}" ] || die "set INFRAMOLE_ENROLLMENT_TOKEN"
export INFRAMOLE_ENROLLMENT_TOKEN
# shellcheck disable=SC2086
"$BIN" install $FLAGS
log "enrolled $(hostname) with $SERVER and started the service"
