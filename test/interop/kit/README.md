# Vendored conformance fake

`test/fake-company.ts` and `jose.ts` are copied from
[personal-agent-protocol/personal-agent-protocol](https://github.com/personal-agent-protocol/personal-agent-protocol)
at commit `7205250`, path `kit/company/validate/`, under the Apache License 2.0, with one `// @ts-nocheck` line added at the top, since
this repository's compiler settings are stricter. `catalog.ts` and
`http.ts` are minimal stubs of the files the fake imports.

The fake is an in-memory Company that follows draft 0.3 of the spec and verifies what a Company
must: delegations, Session JWTs, client assertions, conversations, and browser join. The interop tests
run this SDK against it.

This folder is listed in `.prettierignore`, so the formatter leaves the copies as they are. To
update, copy the two files again from a newer commit, add the `// @ts-nocheck` line, and update the
commit above.
