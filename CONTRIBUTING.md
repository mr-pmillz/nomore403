# Contributing to NoMore403

Contributions are welcome. Useful areas include bug fixes, better payloads, new bypass techniques, raw HTTP improvements, frontend fingerprinting, tests, and documentation.

## Responsible Use

NoMore403 is intended for authorized security testing, bug bounty work, penetration testing, security reviews, and regression testing.

Do not include private target data, credentials, tokens, customer data, or non-public vulnerability details in issues, pull requests, commits, tests, fixtures, or screenshots. Redact real hostnames unless they are intentionally public test targets.

If you need to report a vulnerability in NoMore403 itself, follow [SECURITY.md](SECURITY.md).

## Development Setup

Requirements:

- Go 1.26.6 or later
- `curl` in `PATH` for techniques that exercise curl-based request behavior
- `golangci-lint` for the lint target (CI runs the same config)
- Optional: `docker` and `goreleaser` for the `docker` and `snapshot` targets

Build and test locally:

```bash
make build          # -> bin/nomore403
make test           # go test with a coverage profile
make test-race      # go test -race
make lint           # golangci-lint, same config as CI
```

`make help` lists every target. Run `make all` (lint + test + build) before
opening a pull request; `gofmt -w .` is covered by `make fmt`.

## Branching Model

The repository follows gitflow, enforced by `.github/workflows/branch-policy.yml`:

- feature and fix branches target `develop`
- only `develop`, `release/vX.Y.Z` or `hotfix/vX.Y.Z` may target `main`
- merging a `release/*` or `hotfix/*` PR into `main` tags the release and
  publishes binaries plus the `ghcr.io/mr-pmillz/nomore403` image automatically

## Release Automation (maintainers)

The release path is driven by a GitHub App, mirroring the `sj` repository. The
App matters for two reasons that the default `GITHUB_TOKEN` cannot cover:

- **Tag pushes trigger the release.** GitHub suppresses workflow runs for events
  created by `GITHUB_TOKEN`, so a tag pushed with it would never fire
  `release.yml`. A tag pushed with an App installation token does.
- **Commits are signed.** GitHub signs commits created through the Git Database
  API with an App installation token, so `changelog.yml`'s `chore: update
  changelog` commit lands verified — the workflow fails if it is not.

The App token is also what `git-cliff` authenticates with for its GitHub API
enrichment (`[remote.github]` in `cliff.toml`). GoReleaser and the `ghcr.io`
login still use the default `GITHUB_TOKEN`.

### Required setup

Create a GitHub App owned by the repository owner and install it on this
repository, with these **repository permissions**:

| Permission | Level | Used for |
|---|---|---|
| Contents | Read and write | pushing release tags; creating the changelog blob/tree/commit and fast-forwarding the release branch |
| Pull requests | Read | `git-cliff` resolving commits to pull requests |
| Metadata | Read | mandatory, granted implicitly |

No account permissions, webhooks, or event subscriptions are needed.

Then add two repository **Actions secrets**:

| Secret | Value |
|---|---|
| `NOMORE403_APP_ID` | the App's **Client ID** (e.g. `Iv23li...`) |
| `NOMORE403_APP_PRIVATE_KEY` | the full PEM body of a generated private key, including the `-----BEGIN/END-----` lines |

The workflows pass `NOMORE403_APP_ID` to `actions/create-github-app-token`'s
`client-id` input, so store the Client ID rather than the numeric App ID. To use
the numeric App ID instead, change that input key to `app-id` in `release.yml`,
`tag-release.yml` and `changelog.yml`.

### Cutting a release

1. Branch `release/vX.Y.Z` from `develop`. `changelog.yml` regenerates and
   commits `CHANGELOG.md` on every push to that branch.
2. Open a PR from the release branch into `main` and merge it.
3. `tag-release.yml` derives `vX.Y.Z` from the branch name and pushes the tag.
4. `release.yml` builds the archives, publishes the GitHub release with git-cliff
   release notes, pushes `ghcr.io/mr-pmillz/nomore403:{vX.Y.Z,latest}`, and
   attests provenance for both the archives and the images.
5. Back-merge `main` into `develop`.

## Project Structure

- `cmd/nomore403/`: executable entry point (`package main`)
- `internal/cli/`: command implementation, request logic, bypass techniques, output, and tests
- `payloads/`: payload lists, embedded into the binary at build time
- `payloads.go` / `version.go`: the embedded payload API and build metadata (`package nomore403`)
- `README.md`: user-facing usage and behavior documentation

## Payload Embedding

`payloads.go` embeds the whole `payloads/` directory with `//go:embed`, so the
binary is stand-alone. Adding a file to `payloads/` makes it available to
`nomore403.PayloadLines` on the next build — nothing else needs to change. Load
payloads through `nomore403.PayloadLines` / `nomore403.RandomPayloadLine` rather
than reading from disk, so `-f/--folder` overrides and the embedded fallback keep
working.

## Reporting Bugs

Please use the bug report template and include:

- NoMore403 version or commit SHA
- operating system and architecture
- Go version, if building from source
- exact command and flags, with sensitive data redacted
- expected behavior
- actual behavior
- minimal reproduction steps
- relevant output, preferably with `-v` if it is safe to share

For target-specific behavior, use a local reproduction or a public test target when possible.

## Proposing Features or Techniques

Before adding a new technique, check that it represents a distinct behavior and is not already covered by existing path, header, method, frontend, or raw HTTP logic.

Good technique proposals usually include:

- the parsing, normalization, or trust-boundary behavior being tested
- why the result differs from existing techniques
- an example request shape
- expected signals in output
- tests that verify the generated request shape, filtering, scoring, or replay behavior

## Payload Changes

Payload list changes should stay focused. Avoid adding very large lists unless there is a clear reason and the runtime impact is acceptable.

When adding payloads, prefer entries that are:

- reproducible
- meaningfully different from existing entries
- useful across common frontend, proxy, CDN, WAF, or application stacks
- documented in the pull request when the behavior is not obvious

## Pull Requests

Pull requests should be scoped and easy to review.

Before submitting:

- run `make all` (lint, test, build)
- update documentation if behavior, flags, output, or payload expectations change
- add or update tests for code behavior changes
- target `develop`, not `main`

By contributing, you agree that your contribution will be licensed under the project's MIT License.
