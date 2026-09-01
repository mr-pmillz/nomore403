# Security Policy

## Supported Versions

Security fixes are considered for the current default branch and the latest public release.

Older versions may not receive fixes unless the issue is severe and the patch is practical to backport.

## Reporting a Vulnerability

Please do not open a public issue for vulnerabilities in NoMore403 itself.

Use one of these private reporting paths:

1. Open a private vulnerability report through the repository's GitHub Security tab, if available.
2. If private reporting is not available, contact the maintainer through the contact channel listed on the repository owner's GitHub profile.

Include as much of the following as you can:

- affected version or commit SHA
- operating system and architecture
- impact and attack scenario
- reproduction steps
- proof of concept, if safe to share privately
- whether the issue is already public or known elsewhere
- suggested fix, if you have one

Please do not include secrets, real third-party target data, customer data, or unrelated vulnerability details.

## Release Integrity

Release artifacts are built by GitHub Actions from a tagged commit
(`.github/workflows/release.yml`) using GoReleaser, and published with:

- `checksums.txt` for the archives and `digests.txt` for the container images
- [build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
  for both, verifiable with `gh attestation verify`
- container images signed into `ghcr.io/mr-pmillz/nomore403`

Verify a downloaded archive before use:

```bash
gh attestation verify nomore403_<version>_<os>_<arch>.tar.gz --repo mr-pmillz/nomore403
```

Report anything that looks like a tampered or unexpected artifact through the
private channels above.

## Scope

In scope:

- vulnerabilities in NoMore403's source code, release artifacts, build process, or documentation that could harm users
- command injection, unsafe file handling, unexpected network behavior, data exposure, or supply-chain risks caused by this project
- vulnerabilities in generated output that could mislead users into unsafe handling of sensitive data

Out of scope:

- access-control bypasses found on third-party websites using NoMore403
- reports about systems you are not authorized to test
- scanner output without a clear impact on NoMore403 itself
- denial-of-service reports that only involve intentionally scanning a target at high volume

Report findings on third-party targets to the target owner or their vulnerability disclosure program.

## Disclosure Process

The maintainers will try to acknowledge valid private reports promptly, investigate the issue, and coordinate a fix before public disclosure.

Please allow reasonable time for triage and remediation before publishing details.

## Responsible Use

NoMore403 is intended for authorized security testing. Users are responsible for complying with applicable law, program rules, and organizational policy.
