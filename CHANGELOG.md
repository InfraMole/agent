# Changelog

What changed in each release of `inframole-agent`. Every release is signed:
see the README, "Releases and verification". The agent is read-only and
outbound-only in every version — the server cannot send it commands.

## 0.6.1 — 2026-10-02

### Added

- **Deployment templates** (`deploy/`): a PowerShell script for Group
  Policy, Intune and RMM tools, a shell script for cloud-init, and an
  Ansible playbook. They install the agent once, verify it against
  `SHA256SUMS`, and never enrol a machine twice. The agent itself is
  unchanged.

## 0.6.0 — 2026-10-01

### Added

- **Docker**: containers with their image, published ports and Compose
  project, read from the local Docker API (list endpoint only).
- **Reverse proxies**: upstream targets of nginx, Apache, HAProxy, Traefik
  (container labels) and IIS Application Request Routing.
- **Kubernetes** collector (opt-in): nodes and workloads of a cluster, with
  a read-only ClusterRole.

## 0.5.0 — 2026-09-30

### Added

- Hypervisor collectors (opt-in, Preview): **VMware vCenter / ESXi**,
  **Hyper-V** and **Xen Orchestra (XCP-ng)** — hosts and their VMs.

## 0.4.0 — 2026-09-30

### Added

- Self-update (opt-in from the workspace): the agent installs a new release
  only if its manifest is signed by the InfraMole release key.

## 0.3.0 — 2026-09-30

### Added

- Linux workloads: nginx and Apache sites (names and ports), PostgreSQL and
  MySQL database names (opt-in, local socket authentication).

## 0.2.0 — 2026-09-30

### Added

- Windows workloads: IIS sites (names and bindings) and SQL Server database
  names (opt-in, integrated authentication).

## 0.1.0 — 2026-09-29

First public release.

- Host facts, network interfaces, running services, listening ports and
  aggregated TCP connections, for Windows (service) and Linux (systemd).
- Optional Proxmox VE collector.
- `dry-run` prints exactly what would be sent, and sends nothing.
- Signed releases: SHA256SUMS signed with cosign, build provenance
  attestations, reproducible builds.
