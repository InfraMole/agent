# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately to
**[security@inframole.com](mailto:security@inframole.com)** — do not open a
public issue. Include the affected version, steps to reproduce and the
impact you expect.

We acknowledge reports within 3 working days, keep you informed while we
fix the issue, and credit you in the release notes if you wish.

## Supported versions

Security fixes are released for the latest minor version. Update to the
latest release to receive them.

## Design principles

- The platform never executes commands on your machines; the agent has no
  command channel.
- No passwords, file contents, command-line arguments or environment
  variables are collected.
- Tenant data is isolated in the application and by PostgreSQL row-level
  security.
