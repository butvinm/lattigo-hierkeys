# Security Policy

## Status

This library is **experimental research code** implementing recent
academic work ([LLKN 2022](https://eprint.iacr.org/2022/532),
[KG+ 2025](https://eprint.iacr.org/2025/720)). It has **not** been
independently audited. Functional correctness is covered by tests, but
no third-party cryptographic review has been performed.

Do not rely on this code for production deployments handling real
secrets without independent review.

## Reporting a vulnerability

If you believe you have found a security issue, please open a GitHub
issue on this repository. For sensitive disclosures, contact the
repository owner directly via the email listed on their GitHub profile
before filing a public issue.

Please include:

- A description of the issue and its impact.
- Minimal reproduction steps or a proof-of-concept if available.
- The commit hash or release tag you tested against.

## Supported versions

Only the latest `v0.x` release is supported. The API is considered
unstable until a `v1.0.0` tag is cut.
