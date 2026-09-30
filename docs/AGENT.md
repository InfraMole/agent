# Discovery Agent

Status: **prototype implemented (M5)** in [`/agent`](../agent). Verified on
Windows 11 (non-admin, foreground) and Linux (Alpine container): dry-run,
enroll, report, revocation. **Not yet verified**: running as an installed
Windows service / systemd unit (needs an elevated session), code signing,
self-update.

## 1. Goals

- Tiny, read-only, outbound-only agent for **Windows** and **Linux**.
- Installs in one command, uninstalls cleanly, runs as a service.
- Reports a periodic snapshot of host facts to the backend.
- Never executes commands received from the server. There is no command
  channel: responses carry configuration only, clamped locally.

## 2. Technology: Go (ADR-004)

- Static binaries (~7.5 MB): `windows/amd64`, `linux/amd64`, `linux/arm64`.
- Libraries: `gopsutil/v4` (host, interfaces, TCP table, process name/path),
  `golang.org/x/sys/windows` (Service Control Manager, ACLs, FQDN),
  `kardianos/service` (Windows service / systemd).
- Linux services: `systemctl list-units --type=service --state=running
--no-legend --plain --no-pager` — fixed arguments, never user/server input.

## 3. What is collected

| Data                                                     | Windows                                                                      | Linux                            |
| -------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------- |
| hostname, FQDN, OS name/version, kernel, arch, boot time | gopsutil host + `GetComputerNameEx`                                          | gopsutil host + DNS              |
| machine id (enrollment only)                             | MachineGuid                                                                  | `/etc/machine-id`                |
| interfaces (name, MAC, CIDR addresses), loopback skipped | gopsutil                                                                     | gopsutil                         |
| running services (name, display name, state, start type) | SCM, minimal rights (`SC_MANAGER_ENUMERATE_SERVICE`, `SERVICE_QUERY_CONFIG`) | systemd (no start type)          |
| listening TCP sockets + owning process name/path         | gopsutil (IP Helper)                                                         | gopsutil (`/proc/net/tcp*`)      |
| established TCP connections, aggregated (see §4)         | same                                                                         | same                             |
| IIS sites (name, http/https bindings) — M16, §6c         | `applicationHost.config` (sites section only)                                | —                                |
| SQL Server database names (opt-in) — M16, §6c            | local instances, integrated auth, `sys.databases`                            | —                                |
| nginx / Apache sites (names, ports) — M20, §6d           | —                                                                            | config files (sites only)        |
| PostgreSQL / MySQL database names (opt-in) — M20, §6d    | —                                                                            | local socket, peer / socket auth |

### Never collected

Passwords, credentials, tokens, file contents, browser data, user documents,
**process command lines / arguments**, environment variables, logged-in users,
packet contents. Enforced twice: the Go structs have no such fields, and the
server schema is `.strict()` (unknown fields → 422).

Optional **collectors** (ADR-018 C, §6b) add a platform inventory — for
Proxmox only the fields `id, type (node|qemu|lxc), node, name, vmid, status,
maxmem, template`. Storage, pools, disks, IO counters and everything else
in the API response are dropped by the agent.

Without admin/root, some processes cannot be resolved (listeners appear with
no process); everything else works.

## 4. Sampling vs reporting

- Sample the TCP table every `sampleIntervalSec` (default 30 s).
- Aggregate established connections per `(direction, remote IP, port,
process name)` with `count`, `firstSeen`, `lastSeen`; drop loopback,
  link-local, unspecified and multicast peers; skip non-ESTABLISHED states.
- **Direction**: inbound if the local port has a listener (report `localPort`,
  `remotePort = 0`), else outbound (`localPort = 0`, report `remotePort`).
- Report every `reportIntervalSec` (default 300 s, clamped [60, 3600]); the
  first report is sent right after start so the host appears immediately.
- A failed report drops its window (the next one covers a new window).
- Max 2000 aggregated connections per window (`truncated: true` beyond).

## 5. Protocol v1

Source of truth: `apps/web/src/server/modules/agents/protocol.ts` (zod),
exported to [`agent/contract/report.v1.schema.json`](../agent/contract/report.v1.schema.json).
The Go golden report (`agent/internal/protocol/testdata/report.golden.json`)
is validated against zod by a web unit test (`contract.test.ts`).

All requests: HTTPS JSON, `User-Agent: inframole-agent/<version> (<os>/<arch>)`.
The client refuses redirects (so the bearer secret cannot leak) and plain
http unless `--insecure-dev`.

`POST /api/agent/v1/enroll` (rate limit 10/min/IP, body ≤ 8 KB)

```json
{
  "enrollmentToken": "dmp_enr_…",
  "machineId": "…",
  "hostname": "APP01",
  "os": "windows",
  "osVersion": "…",
  "arch": "amd64",
  "agentVersion": "0.1.0"
}
```

→ `201 { "agentId", "agentSecret": "dmp_agt_…", "config": { "reportIntervalSec": 300, "sampleIntervalSec": 30 } }`
→ `401` invalid/expired/revoked/exhausted token (no detail) · `422` · `415` · `429`.
Re-enrolling the same machine (workspace + machineId) reuses the agent and
rotates its secret (old secret → 401).

`POST /api/agent/v1/report` with `Authorization: Bearer dmp_agt_…`
(rate limit 10/min/agent, body ≤ 1 MB): see the JSON Schema. Top level:
`schemaVersion, agentVersion, collectedAt, windowStart, host, interfaces[],
services[], listeners[], connections[], truncated?`.
→ `202 { "config": {…} }` · `401` (unknown/revoked → the agent stops
reporting) · `413` · `415` · `422` (invalid or unsupported schema version) ·
`429` (agent waits `Retry-After`).

## 6. Local configuration

JSON (stdlib only): `C:\ProgramData\InfraMole\agent.json` or
`/etc/inframole/agent.json` (override with `--config`):

```json
{
  "server": "https://…",
  "agentId": "…",
  "agentSecret": "dmp_agt_…",
  "reportIntervalSec": 300,
  "sampleIntervalSec": 30
}
```

Permissions: Linux dir `0700`, file `0600`; Windows protected DACL
`SYSTEM + Administrators + OWNER RIGHTS` (verified with `icacls`). Written
atomically. Server-provided intervals are clamped and persisted.

### 6b. Collectors (ADR-018 C) ✅ M8b

Enabled **only by editing the local config file** — the server cannot turn
them on, change their URL or read their credentials (there is still no
command channel). Credentials never leave the machine.

```json
{
  "…": "…",
  "collectors": {
    "proxmox": {
      "url": "https://pve01.lan:8006",
      "tokenFile": "/etc/inframole/proxmox.token",
      "caFile": "/etc/inframole/pve-ca.pem",
      "intervalSec": 3600
    }
  }
}
```

- Create a Proxmox API token for a dedicated user with the **PVEAuditor**
  role on `/` (read-only), with privilege separation. Put
  `USER@REALM!TOKENID=SECRET` in `tokenFile`.
- `tokenFile` must be private: Linux `chmod 600` (the agent refuses a
  group/world-readable file); Windows: same ACL as `agent.json`
  (`icacls proxmox.token /inheritance:r /grant:r SYSTEM:F Administrators:F`).
- TLS: https only; trust the PVE CA with `caFile` (`/etc/pve/pve-root-ca.pem`
  on the node). `"insecureSkipVerify": true` exists for self-signed labs and
  is only settable locally. Redirects are never followed; 30 s timeout; 16 MB
  response cap.
- Cadence: `intervalSec` (default 3600, clamped to 300–86400). The
  inventory rides on the next report; if that report fails, the next one
  collects again. Collection errors are logged locally and never block host
  reports.
- Test without sending anything to InfraMole:
  `inframole-agent dry-run --inventory --window 2s`.
- Server side: `report.inventory` is fed to the importer pipeline
  (actor AGENT = this agent): nodes / VMs / LXC arrive as DISCOVERED,
  node HOSTS guest as CONFIRMED (origin DETECTED), idempotent. A guest that
  runs the agent itself is matched to the agent's host by name (its type is
  kept).

### 6c. Windows workloads ✅ M16 (ADR-028)

`internal/workloads`, collected hourly (`collectors.workloads.intervalSec`,
300–86400) and sent only after the server listed `"workloads"` in the
`features` of a response (enroll / report): an older server rejects unknown
report fields, so the first report of a run never carries them. If a report
with workloads is rejected (422), the agent stops sending them for that run.

- **IIS sites** (default on; `"iis": false` turns it off): parsed from
  `%windir%\System32\inetsrv\config\applicationHost.config` with a
  streaming XML decoder that keeps only `sites/site@name` and
  `bindings/binding@protocol,bindingInformation` for http/https. Paths,
  pools, identities and encrypted passwords in that file are never decoded
  (unit test with a fixture full of them).
- **SQL Server databases** (opt-in: `"sqlServer": true`): instances from
  `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`;
  per instance, go-mssqldb (Windows build only: +1.7 MB) connects locally
  (shared memory / named pipes / loopback, `encrypt=false`,
  `TrustServerCertificate=true`) with **integrated authentication** as the
  service identity, and runs only `SELECT name FROM sys.databases WHERE
database_id > 4`. No credentials are stored. The query was verified
  against SQL Server 2022 (`go test -tags mssqllive`); integrated auth and
  instance discovery still need a check on a real Windows SQL Server.
- A present array is a full snapshot ("none" = `[]`, never `null`); an
  absent one = not collected (the server leaves that kind alone).
- Server side: `ingestion.ts#importWorkloads` → importer format
  `workloads` (`parse-platforms.ts`), one source per kind
  (`collector:<agentId>:iis|mssql`, reconciled → missing = STALE). Sites →
  APPLICATION `"<site> (<HOST>)"` with `metadata.ports` and `fqdn` (first
  binding host); databases → DATABASE `"<db> (<HOST>[\<INSTANCE>])"`; both
  RUNS_ON the host (CONFIRMED, origin DETECTED); the host is referenced as
  `id:<resourceId>` (planner resolves only resources of the workspace).
  Discovery attributes a connection to a host port that exactly one workload
  listens on to that workload (`plan.ts#attributeToWorkload`), unless the
  host pair already has a relationship.

### 6d. Linux workloads ✅ M20 (ADR-031)

Same model as §6c, sent only when the server also lists
`"workloads-linux"` in `features` (older servers get the Windows fields
only).

- **nginx** (default on with `webServers`): `ParseNginx` tokenises
  `/etc/nginx/nginx.conf` and follows `include` globs (≤ 200 files, depth
  10, 2 MB each); only `server` blocks outside `stream{}` / `mail{}` and in
  them `listen` / `server_name` (no listen = port 80; unix sockets
  skipped; `ssl` / `quic` → https). Blocks are merged by their primary name.
- **Apache**: `ParseApache` on `/etc/apache2/apache2.conf` (Debian) or
  `/etc/httpd/conf/httpd.conf` (RHEL), following `Include` /
  `IncludeOptional` from `ServerRoot`; only `<VirtualHost>` addresses,
  `ServerName`, `ServerAlias`, `SSLEngine`.
- **PostgreSQL** (opt-in `postgresql`): every `.s.PGSQL.<port>` socket in
  `/var/run/postgresql`, `/run/postgresql`, `/tmp`; a minimal v3 client
  (`pgwire.go`, no dependency) starts up as the OS user (peer auth), runs
  `SELECT datname FROM pg_database WHERE NOT datistemplate` and terminates;
  any password request → `ErrPasswordRequired`.
- **MySQL / MariaDB** (opt-in `mysql`): the first socket of
  `/run/mysqld/mysqld.sock`, `/var/run/mysqld/mysqld.sock`,
  `/var/lib/mysql/mysql.sock`, `/tmp/mysql.sock`; a minimal client
  (`mysqlwire.go`) logs in with an empty response and follows an
  AuthSwitch only to `unix_socket` / `auth_socket`; runs `SHOW DATABASES`.
- System databases are dropped by the agent (and the server). Verified
  inside real containers: nginx, ubuntu/apache2, PostgreSQL 17 (peer),
  MariaDB 11 (unix_socket), MySQL 8.4 (auth_socket; password accounts
  refused with a clear warning). No new Go dependency (the MySQL driver is
  MPL-2.0, not allowed).

## 7. CLI

```
inframole-agent dry-run [--window 10s] [--inventory] # prints the report; nothing sent to InfraMole
inframole-agent enroll  --server URL --token TOKEN  # or INFRAMOLE_ENROLLMENT_TOKEN
inframole-agent run [--once] [--window 10s]         # foreground (service mode auto-detected)
inframole-agent install --server URL --token TOKEN  # enroll + install + start service
inframole-agent uninstall [--keep-config]
inframole-agent status | version
```

`--insecure-dev` allows `http://` (local testing only). In service mode, a
revoked credential makes the agent log an error and idle (no restart loop).
Logs: stderr (foreground) or the OS service log (Event Log / journal).

## 8. Privileges

Admin/root is recommended only because the OS requires it to map every socket
to its process. The agent writes nothing outside its config directory.
Future: Linux capabilities instead of root.

### 8b. Service install verified (2026-09-29)

- **Windows 11** (elevated): `install` enrolled, registered `inframole-agent`
  (LocalSystem, automatic start, `"C:\Program Files\InfraMole\inframole-agent.exe" run
--config C:\ProgramData\InfraMole\agent.json`) and started it; the first
  report appeared in the Application event log; `status` showed "running";
  config and directory ACL = SYSTEM + Administrators + OWNER RIGHTS only;
  survives `Restart-Service`; `uninstall` removed the service and the config.
- **Linux / systemd** (Debian, systemd as PID 1 in a container): unit
  `/etc/systemd/system/inframole-agent.service` enabled (`WantedBy=multi-user.target`,
  `Restart=always`, `RestartSec=120`); `/etc/inframole` 0700, `agent.json`
  0600; logs in journald; after `SIGKILL` systemd restarted it (NRestarts=1)
  and it reported again; `uninstall` removed the unit and the config.
- Note: `uninstall` does not revoke the credential server-side — revoke the
  agent in Settings › Agents (the CLI says so).

## 9. Not yet done

- Self-update (needs a signed manifest; ADR first).
- Persisting a failed report window for retry.

## 10. Releases & verification ✅ M8b

Published from the **public repo `InfraMole/agent`** (ADR-024, docs/OPEN_SOURCE.md):
`publish.yml` here exports `agent/` as that repo's root and tags `vX.Y.Z` → its
`.github/workflows/release.yml` (template: `scripts/publish/templates/workflows/agent-release.yml`).
Go module path: `github.com/InfraMole/agent`. Licence AGPL-3.0-only.

1. `go vet` + `go test`, then `scripts/release.sh`: windows/linux ×
   amd64/arm64, `CGO_ENABLED=0 -trimpath -buildvcs=false`,
   `-ldflags "-s -w -buildid= -X main.version=X.Y.Z"` — **reproducible**
   (two builds give identical hashes). Asset names have no version
   (`inframole-agent_linux_amd64`, `inframole-agent_windows_amd64.exe`, …) so
   `…/releases/latest/download/<asset>` works.
2. Optional **Authenticode** for the `.exe` files (osslsigncode + RFC 3161
   timestamp) when the secrets `WINDOWS_CODESIGN_PFX_BASE64` and
   `WINDOWS_CODESIGN_PASSWORD` exist. Without a certificate, Windows
   SmartScreen may warn; the signed checksums still protect integrity.
3. `SHA256SUMS`, signed **keyless with Sigstore** (`cosign sign-blob`, GitHub
   OIDC identity, logged in Rekor) → `SHA256SUMS.sigstore.json`.
4. GitHub **build provenance** attestation for every binary.

Verify by hand:

```bash
sha256sum --ignore-missing -c SHA256SUMS
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/\.github/workflows/agent-release\.yml@refs/tags/agent-v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
gh attestation verify inframole-agent_linux_amd64 --repo <owner>/<repo>
```

The service runs the binary from where `install` was called, so the
generated commands (M12) first put it in a permanent place:
`%ProgramFiles%\InfraMole\inframole-agent.exe` and `/usr/local/bin/inframole-agent`
(verified for real: genuine binary installed, tampered one refused and
removed, on PowerShell and in a Debian container).

In the web app, set `AGENT_DOWNLOAD_BASE_URL` (e.g.
`https://github.com/<owner>/<repo>/releases/latest/download`): the
enrollment sheet then shows direct download links and install commands
that **download the binary and `SHA256SUMS` and stop on a mismatch**
before installing (`lib/agent-install.ts`; tested for real on Windows
PowerShell and Linux with a genuine and a tampered binary).
