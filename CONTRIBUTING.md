# Contributing to InfraMole

Thank you for your interest in InfraMole! Bug reports, ideas, documentation
fixes and code are all welcome.

## Issues

- **Bugs**: open an issue with the _Bug report_ form — version, how you run
  InfraMole, steps to reproduce. Never paste tokens, passwords or other
  secrets; remove them from logs and screenshots.
- **Ideas**: the _Feature request_ form. Tell us the problem first; the
  solution can come later.
- **Security problems**: never in a public issue — see
  [SECURITY.md](SECURITY.md).

## Pull requests

1. **Open an issue first** for anything larger than a small fix, so we can
   agree on the approach before you spend time on it.
2. Keep the product principles: read-only towards infrastructure (no remote
   command execution), no secrets or personal data collected, and a
   suggestion is never presented as a confirmed dependency.
3. Run the checks described in the README and add tests for new behaviour.
4. Start new source files with `SPDX-License-Identifier: AGPL-3.0-only`.
5. Describe user-visible changes; maintainers add them to `CHANGELOG.md`.

## Contributor License Agreement

InfraMole is licensed under the **AGPL-3.0-only**, and Alejandro Galisteo
also offers it under a **commercial licence** to organisations that cannot
accept the AGPL. To keep that possible, every contribution needs the
[Contributor License Agreement](CLA.md) (CLA). In short: you keep the
copyright in your work, you allow it to be distributed under the AGPL and
under commercial terms, and every contribution included in a release is
always also available under the AGPL or another OSI-approved licence.

When you open your first pull request, a check asks you to accept it by
posting one sentence as a comment. You only do it once.

## Third-party code

Do not copy code from other projects unless its licence is permissive and
compatible with the AGPL (MIT, BSD, ISC, Apache-2.0…) and you keep its
notice. New dependencies must be listed with their licence in `NOTICE`.
Copyleft dependencies other than the LGPL, and anything "source available"
(BSL, SSPL, Commons Clause…), are not accepted: they would prevent the
commercial licence.
