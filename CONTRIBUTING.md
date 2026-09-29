# Contributing to InfraMole

Thank you for helping! Bug reports, documentation fixes and pull requests are
welcome.

## Before you open a pull request

1. **Open an issue first** for anything larger than a small fix, so we can
   agree on the approach.
2. Keep the product principles: read-only towards infrastructure (no remote
   command execution), no secrets or personal data collected, never present a
   suggestion as a confirmed dependency.
3. Run the checks described in the README; add tests for new behaviour.
4. Add `// SPDX-License-Identifier: AGPL-3.0-only` at the top of new source
   files.

## Contributor License Agreement (required)

InfraMole is licensed under the **AGPL-3.0-only**, and Alejandro Galisteo
also offers it under a **commercial licence** to organisations that cannot
accept the AGPL. To keep that possible, every contribution must be covered by
a Contributor License Agreement:

> By submitting a contribution (a pull request, patch or any other material)
> to this repository, you certify that you wrote it or have the right to
> submit it, and you grant Alejandro Galisteo and its successors a
> perpetual, worldwide, non-exclusive, royalty-free, irrevocable licence to
> use, reproduce, modify, sublicense and distribute your contribution under
> the AGPL-3.0-only **and under other licence terms, including proprietary
> commercial licences**. You keep the copyright in your contribution, and it
> will always also be available under the AGPL-3.0-only.

Pull requests are only merged when the author has agreed to this CLA (the
pull request template asks you to confirm it).

**Draft — pending legal review.** Until the CLA text is final, we may ask you
to confirm again before merging.

## Third-party code

Do not copy code from other projects unless its licence is permissive and
compatible with the AGPL (MIT, BSD, ISC, Apache-2.0…) and you keep its
notice. New dependencies must be listed with their licence in `NOTICE`.
Copyleft dependencies other than the (L)GPL family, and anything "source
available" (BSL, SSPL, Commons Clause…), are not accepted: they would prevent
the commercial licence.

## Security issues

Do **not** open a public issue. See `SECURITY.md`.
