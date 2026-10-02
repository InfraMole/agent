<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deploying the agent to many machines

Templates for installing the InfraMole agent on many servers at once. All of
them are **idempotent** — safe to run on every start-up or on every play:

- a machine that is already enrolled is never enrolled again;
- a stopped service is started; a removed service is reinstalled with the
  existing credential;
- the binary is verified against `SHA256SUMS` before it is ever run;
- the enrollment token is passed through the environment, never on a
  command line.

| File                                 | For                                                      |
| ------------------------------------ | -------------------------------------------------------- |
| `windows/Install-InfraMoleAgent.ps1` | Group Policy startup script, Intune platform script, RMM |
| `linux/install-inframole-agent.sh`   | cloud-init, RMM, a loop over ssh                         |
| `ansible/inframole-agent.yml`        | Ansible (Linux hosts; pins or follows agent versions)    |

Step-by-step guide (Group Policy, Intune, Ansible, a mirror for machines
without internet access, and how to roll back):
**https://inframole.com/docs/agent/mass-deployment**

Use an enrollment token with an expiry and a maximum number of agents, and
revoke it when the rollout is done — a token placed in a GPO or a script
can be read by others.
