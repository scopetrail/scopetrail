# Contributing to ScopeTrail

Thanks for considering a contribution.

## License of your contribution

This project is licensed under the Apache License, Version 2.0 (see
`LICENSE`). Contributions are accepted under that same license, and the
license is not going to change — `@scopetrail/core` stays Apache-2.0
permanently. That permanence is the point: it's what lets OEM partners and
downstream products embed the library without copyleft or relicensing risk.

## No CLA required

We do **not** require a Contributor License Agreement. There is no
assignment of copyright and no separate signature process to complete
before a pull request can be reviewed.

## DCO sign-off is required instead

Instead of a CLA, contributions must include a **Developer Certificate of
Origin (DCO)** sign-off. The DCO is a lightweight statement that you wrote
the contribution, or otherwise have the right to submit it under the
project's license. Full text: https://developercertificate.org/

To sign off, add a `Signed-off-by` line to your commit message. The
easiest way is to let Git do it for you:

```
git commit -s -m "Describe your change"
```

This appends a line like:

```
Signed-off-by: Your Name <you@example.com>
```

Make sure the name and email match your Git configuration
(`git config user.name` / `git config user.email`). Unsigned commits will
not be merged.

## Making a change

1. Fork the repo and create a branch for your change.
2. Keep changes focused — small, reviewable PRs merge faster than large ones.
3. Add or update tests for anything behavior-affecting (`npm test`).
4. Sign off every commit (`git commit -s`).
5. Open a pull request describing what changed and why.

## Scope note

The signing/canonicalization path (`src/signer.ts`, JCS canonicalization,
Ed25519 signing/verification, and anything that affects the bytes of a
signed receipt) is treated as especially sensitive — changes there get
extra scrutiny, since altering it could break verification of receipts
already issued. If you're proposing a change in that area, please open an
issue to discuss the approach before sending a PR.
