# Contributing

Thanks for helping. Bug reports, fixes and spec-conformance improvements are welcome.

## Setup

You need Node.js 22.12 or later (for the dev tools) and pnpm (the version is pinned in `package.json`; `corepack enable` picks it up).

```sh
pnpm install
pnpm run test
```

## Before you open a pull request

```sh
pnpm run format     # oxfmt
pnpm run lint       # oxlint
pnpm run typecheck  # tsc
pnpm run test       # vitest
```

CI runs the same checks on Node.js 22, 24 and 26.

## Guidelines

- **Follow the spec.** Behavior comes from the [Personal Agent Protocol specification](https://personalagentprotocol.org/docs/spec.md), not from any one Company's server. Cite the section in code comments where a rule is not obvious.
- **No runtime dependencies.** The SDK uses `fetch` and WebCrypto only. Dev dependencies are pinned to exact versions.
- **Test against a Company that checks.** `test/interop/` runs the SDK against the spec project's conformance fake, and `test/mock-company.ts` covers the signed-in flows the fake doesn't. New behavior gets a test in one of them, including the error paths. [docs/interop.md](docs/interop.md) says which covers what.
- **Keep secrets out of errors and logs.** Tokens, device codes and assertions live in private fields and never appear in error messages.
- **One change per pull request**, with a commit message in the imperative mood.

## Releases

[release-please](https://github.com/googleapis/release-please) reads the Conventional Commit messages on `main` (`feat:`, `fix:`, `feat!:`) and keeps a release pull request open with the next version and changelog. Merging that pull request tags the release, and `.github/workflows/release.yml` then publishes to npm through [trusted publishing](https://docs.npmjs.com/trusted-publishers) (GitHub OIDC, no npm token). npm adds a provenance attestation once the repository is public. Nothing is published on other pushes.

The workflow needs:

- Repository secrets `RELEASE_APP_ID` and `RELEASE_APP_PEM`: the GitHub App that opens the release pull request.
- A trusted publisher on npmjs.com for `@descope/poppy` (package Settings, Trusted publishing, GitHub Actions): organization `descope`, repository `poppy-js`, workflow `release.yml`, no environment, `npm publish` allowed.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
