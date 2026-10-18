# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Discovery of a Company's `poppy.json` and OAuth metadata, with the checks the spec requires.
- `clientMetadata()` and `jwks()` to build the agent's client metadata document and key set.
- `PoppyAgent` and `Session`: signed-out Sessions with JWT bearer assertions, renewing with the Account Token or a fresh assertion, and sign-out.
- Device Sign-In with `slow_down` handling, a deadline and `AbortSignal` support.
- `Session.fetch` for DPoP-bound API calls, limited to the Company's hosts.
- `Store` interface and `MemoryStore`.
- `PoppyAgent.forget` to sign a User out at a Company and delete their stored state.
