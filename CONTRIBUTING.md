# Contributing

Thanks for helping. Bug reports, fixes and spec-conformance improvements are welcome.

## Setup

You need Node.js 22 or later and pnpm (the version is pinned in `package.json`; `corepack enable` picks it up).

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
- **Test against the mock Company.** `test/mock-company.ts` verifies signatures, DPoP proofs and assertions the way a Company must. New behavior gets a test there, including the error paths.
- **Keep secrets out of errors and logs.** Tokens, device codes and assertions live in private fields and never appear in error messages.
- **One change per pull request**, with a commit message in the imperative mood.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
