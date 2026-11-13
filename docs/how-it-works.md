# How it works

This page follows a request from discovery to a signed-in API call, then covers the rest of the protocol: browser join, conversations and operations. Section numbers refer to [spec 0.4](https://personalagentprotocol.org/docs/0.4/spec), and name 0.3 where the two differ.

- [The parties](#the-parties)
- [Discovery](#discovery)
- [Users, Sessions and the Session header](#users-sessions-and-the-session-header)
- [Signing in](#signing-in)
- [Sending a request](#sending-a-request)
- [Joining a browser](#joining-a-browser)
- [Conversations](#conversations)
- [Operations](#operations)

## The parties

A **User** is the person your agent acts for. Your **Personal Agent** is identified by its `client_id`, the HTTPS URL of a metadata document you publish, and it signs with keys from the `jwks_uri` that document names. A **Company** publishes `poppy.json`, and may run an OAuth issuer, APIs, MCP servers, a website and a **Company Agent**.

In the SDK, a `PoppyAgent` is your Personal Agent, a `PoppyUser` is one of your Users at one Company, and a `Session` is one stretch of that User's activity there.

```mermaid
flowchart TD
    Agent["PoppyAgent<br/>client_id, signing key, store"]
    Company["Company<br/>from agent.discover()"]
    User["PoppyUser<br/>pairwise User ID, refresh token"]
    S1["Session<br/>sid A"]
    S2["Session<br/>sid B"]
    Agent -->|"discover(website)"| Company
    Agent -->|"user(company, yourUserId)"| User
    User -->|"session()"| S1
    User -->|"session()"| S2
```

A User can have several Sessions at once, for tasks running in parallel. They share the User's sign-in.

## Discovery

`agent.discover("example.com")` fetches the Company's documents and checks them before the SDK sends the Company anything (spec 3).

```mermaid
sequenceDiagram
    autonumber
    participant SDK as Poppy SDK
    participant Domain as example.com
    participant Issuer as auth.example.com

    SDK->>Domain: GET /.well-known/poppy.json
    Domain-->>SDK: poppy.json (redirects must end at the well-known path)
    Note over SDK: the newest version both serve<br/>organization.domain is the host that served it
    SDK->>Domain: GET /.well-known/oauth-protected-resource
    Domain-->>SDK: resource, authorization_servers
    Note over SDK: 404 or no servers: no issuer, signed-out only<br/>several servers: auth.issuer picks one
    SDK->>Issuer: GET /.well-known/oauth-authorization-server
    Issuer-->>SDK: issuer, endpoints, grant types, protected_resources
    Note over SDK: issuer matches exactly<br/>protected_resources lists https://example.com
```

The domain names its issuer, and the issuer lists the domain back, so one domain can't claim another Company's issuer and receive its tokens. The result is a `Company` with:

- `identifier`: the issuer, or `https://{domain}` for a Company without one. Session JWTs are addressed to it, and User IDs are scoped by it.
- `name`, `domain` and `logoUri`, which you show the User together.
- `signIn`: which of Direct, Device and Mediated Sign-In the Company offers. All of them are off when the Company sets `auth.disabled`, and the SDK then refuses to start sign-in (spec 3.2).
- `protocolVersion`: the version negotiated with this Company, which everything below follows.
- `apis`, `conversationProtocols`, `browserSessionEndpoint` and `extensions`.
- `scopes` and `scopeHints`, which describe what each scope allows. `supportedScopes(company)` adds the scopes the issuer and the domain's protected resource metadata list, either of which may name one from 0.4.
- `tasksEndpoint` on 0.4, or `feedbackEndpoint`, `excludedTasksUrl` and `skills` on 0.3. Read them through `session.taskCoverage()`, which works the same on both. `session.fetchSkill(name)` fetches a skill with no credentials and checks its digest. A skill explains how to do a task through the Company's APIs, but it grants no access and no approval (spec 9.4).
- `ucp`, when the Company lists the UCP extension. See [UCP](ucp.md).

### Protocol versions

A Company serves one version in `poppy.json` and may list others in `supported_versions`, each mapped to that version's document (spec 3.4). `discover()` picks the newest of them this SDK implements — `SUPPORTED_PROTOCOL_VERSIONS` is `["0.4", "0.3"]` — and reads that version's document. A linked document is used only when its URL is HTTPS on the host that served `poppy.json`, it doesn't redirect, it carries the `protocol_version` it was listed under, and it has no `supported_versions` of its own; one that fails any of these is dropped, and the next newest version is used instead.

`company.protocolVersion` records what was chosen, and from 0.4 every request with the Session header carries it in `Poppy-Version`, with the extensions the agent uses in `Poppy-Extensions`, the same throughout a Session. If a Company answers `version_unsupported`, `session.fetch()` discovers it again without a cached copy and, when that chooses another version, continues in a new Session at that version and sends the request once more.

Two areas behave differently on each version, and the SDK gives you one API for both:

|                       | 0.3                                                                         | 0.4                                                                                   |
| --------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Task coverage         | `excluded_tasks.url`, `skill_index` and `feedback.endpoint` in `poppy.json` | one `tasks.endpoint`, fetched per Session with the Session header and no access token |
| Conversation state    | one `status`: `working`, `idle`, `queued` or `closed`                       | `working`, `handoff`, `responder` and `closed`, which can hold at once                |
| Conversation requests | each message carries its own `id`                                           | every POST carries a request `id`, and a message's ID is its request's                |
| Withdrawing a handoff | not available                                                               | `conversation.cancelHandoff()`                                                        |
| Extensions            | listed in your client metadata document                                     | declared per request in `Poppy-Extensions`                                            |

`conversation.status` still reports a 0.3 status on both versions, derived from the state, so code written for 0.3 keeps working.

## Users, Sessions and the Session header

`agent.user(company, "your-own-user-id")` returns the User's **User ID** at that Company. The SDK generates it at random the first time and keeps it in your store, so it's stable, different at every Company, and not derived from anything personal (spec 5.1). The Company never sees your own user ID.

`user.session()` opens a Session. It makes no request: the SDK picks a random `sid`, and the Session starts at the Company when the first request carrying it arrives (spec 5.2). One Session belongs to one User at one Company, so a `sid` is never carried to another of either. Run several at once for tasks in parallel; they share the account's sign-in.

### Carrying a Session across processes

A Session lasts until you stop using its `sid` (spec 5.5), not until a process exits. An agent that doesn't stay running — a CLI, a queue worker, a serverless handler — would otherwise open a new Session for every invocation, and the Company would see one User's activity as a crowd of unrelated Sessions, with the cart and the open conversation each belonging to one that never comes back.

Save `session.id` with the version it ran under, and pass both back:

```typescript
const session = user.session({ id: savedId, protocolVersion: savedVersion });
// ... use it ...
await save(session.id, session.protocolVersion); // read both back: either can have changed
```

Three things a resumed `sid` needs, and the SDK can only check the last two:

- **A persistent store and the same `localUserId`.** The Session JWT's `sub` is the pairwise User ID, which `PoppyAgent` keeps in its store — and the default store is `MemoryStore`, which a new process starts empty. A CLI that resumes a `sid` without a persistent `store` signs it under a different `sub`, and the Company answers `invalid_session` on every request. Give `PoppyAgent` a real store, and ask for the same User.
- **The same protocol version.** A Session uses one version throughout (spec 3.4). Pass the version you saved: if the Company now serves another one, the SDK starts a new Session rather than sending the old `sid` under a version it never used. Compare `session.id` with what you passed to see which happened.
- **A User that isn't anonymous.** `anonymousUser()` mints a new User ID every time, so there is nothing to continue; `session({ id })` throws there rather than letting the old `sid` go out under a new `sub`.

If the Company has ended the Session, the next request gets `session_ended` and the SDK starts a new one with a new `sid` and sends the request again, once — so read `session.id` back after a request rather than assuming the one you passed in is still current. Once a Session has ended, on either side, stop using its `sid` (spec 5.5): don't pass it to `session({ id })` again.

Every request to the Company's APIs, conversations and other protocol endpoints carries a `Poppy-Session` header: a JWT signed fresh for that one request (spec 5.2). Your signing key doesn't sign it directly. Instead, it signs a short-lived **delegation** that vouches for a **delegated key**, and the delegated key signs the Session JWTs.

```mermaid
flowchart LR
    Root["Your signing key<br/>(in jwks_uri)"]
    Delegation["Delegation JWT<br/>typ poppy-delegation+jwt<br/>cnf.jwk = delegated public key<br/>lifetime at most 24h<br/>names no User or Company"]
    DKey["Delegated key<br/>one set per User ID"]
    SJWT["Session JWT, one per request<br/>typ poppy-session+jwt<br/>aud, sid, sub, htm, htu, iat, jti<br/>ath when signed in"]
    Root -->|signs| Delegation
    Delegation -->|vouches for| DKey
    DKey -->|signs| SJWT
    Delegation -.->|"carried in poppy_dlg header"| SJWT
```

This keeps your signing key away from anything that names a User or a Company, and limits a leaked delegated key to one User at one Company until its delegation expires (spec 10.7). The SDK renews delegations before they expire and keeps delegated keys in memory only.

## Signing in

A Session starts signed out. When a task needs the User's account, the User signs in with OAuth, and the SDK stores the refresh token for the account (spec 4). Sign-in doesn't belong to one Session: every Session of the User uses it.

### Direct Sign-In

Direct Sign-In (spec 4.2) is the authorization code grant with PKCE. The User signs in on the Company's own page.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Your agent
    participant SDK as Poppy SDK
    participant Issuer as Company issuer

    App->>SDK: user.startDirectSignIn({ scope })
    SDK->>SDK: PKCE verifier, state, pending record in store
    SDK-->>App: authorization URL
    App->>User: open the URL in their browser
    User->>Issuer: sign in, approve scopes
    Issuer-->>App: redirect to redirect_uri with code, state, iss
    App->>SDK: agent.completeDirectSignIn(company, callbackUrl)
    SDK->>SDK: check state and iss (RFC 9207)
    SDK->>Issuer: POST token: code, code_verifier, client assertion
    Issuer-->>SDK: access token, refresh token, scope
    SDK->>SDK: check scope, store refresh token
    SDK-->>App: granted scopes
```

The pending record lives in your store, so the callback can be handled by another process that shares it. A new sign-in requests the scopes the User already granted plus the new ones, and revokes the refresh token it replaces.

### Device Sign-In

Device Sign-In (spec 4.3) suits agents that can't receive a browser redirect. The User signs in on any device with a link and a short code.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant SDK as Poppy SDK
    participant Issuer as Company issuer

    SDK->>Issuer: POST device authorization: scope, client assertion
    Issuer-->>SDK: device_code, user_code, verification_uri
    Note over SDK: link host must be the issuer's or a protected resource's
    SDK-->>User: Company name, domain, link and code
    loop every interval
        SDK->>Issuer: POST token: device_code, client assertion
        Issuer-->>SDK: authorization_pending or slow_down
    end
    User->>Issuer: open link, sign in, approve
    SDK->>Issuer: POST token
    Issuer-->>SDK: access token, refresh token
```

The device code never leaves the `DeviceSignIn` object. Prefer Direct Sign-In when you can, since a device code is easier to use for phishing.

### Mediated Sign-In

Mediated Sign-In is a transitional extension for Companies that offer neither of the above. The User gives your agent credentials for that Company, and `user.mediatedSignIn()` sends them only to the issuer's token endpoint. If the Company sends the User a one-time code, the result has `status: "code_required"` and a `submitCode()` function.

### Refresh, sign-out and accounts

- Access tokens stay in memory. The SDK refreshes them when they expire, uses a rotated refresh token from then on, and continues signed out if refresh returns `invalid_grant` (spec 4.4, 5.5).
- `user.signOut()` revokes the refresh token. Sessions carry on signed out.
- Separate accounts at one Company, such as personal and business, use `agent.user(company, id, { account: "business" })`, each with its own refresh token.

## Sending a request

`session.fetch()` is a `fetch` that speaks Poppy. It works out which token the request needs, signs the Session JWT, and handles the retries the spec defines.

```mermaid
flowchart TD
    Start(["session.fetch(url, init)"]) --> Host{"A URL poppy.json<br/>lists or its APIs describe?"}
    Host -->|no| Refuse(["throw PoppyProtocolError"])
    Host -->|yes| Signed{"Signed in and<br/>not signedOut?"}
    Signed -->|no| Sign
    Signed -->|yes| Resource["Find the service's resource<br/>(MCP url, OpenAPI server,<br/>conversation endpoint)"]
    Resource --> Token["Access token for that resource,<br/>refreshing if needed"]
    Token --> Sign["Sign a Session JWT<br/>(ath covers the token)"]
    Sign --> Send["Send with Poppy-Session,<br/>Authorization and DPoP"]
    Send --> Status{"Response"}
    Status -->|"400 session_ended (once)"| NewSid["New sid"] --> Sign
    Status -->|"401 use_dpop_nonce (once)"| Sign
    Status -->|"401 invalid_token (once)"| Refresh["Drop the token,<br/>refresh"] --> Signed
    Status -->|anything else| Done(["return the Response"])
```

- **Where the Session header goes.** Only to URLs the Company's `poppy.json` lists, or that its APIs describe: an OpenAPI description's server, an MCP server, the conversation endpoint and its routes, and the other endpoints it names (spec 5.2). Another path on the same host gets no Session header. When an OpenAPI description can't be loaded, requests to that API fail until it can.
- **Ended and invalid Sessions.** On `session_ended`, the SDK starts a new Session with a new `sid` and sends the request once more. The old Session's state, such as a cart, doesn't carry over, but conversations do (spec 5.5). `invalid_session` comes back to you without a retry, since a new Session doesn't fix it (spec 5.3).
- **Which token.** By default one access token works at all of a Company's services. A service whose protected resource metadata names its own `resource`, as every MCP server does, gets a token issued for it (spec 4.5, RFC 8707).
- **Bearer or DPoP.** If the issuer lists ES256 for DPoP, token requests carry a proof. The issuer decides whether to bind each token, and the SDK sends it as its `token_type` says, including at MCP servers (spec 4.5). An MCP server without protected resource metadata offers no account access, so it gets no token.
- **Redirects** are returned to you, never followed, so a token or Session JWT never reaches another URL (spec 3).
- **Other errors** come back as the `Response`. `scopesNeeded(response)` tells you which scopes to sign in for, and `authChallenge(response)` reads the full `WWW-Authenticate` challenge.

To use an MCP server, pass `session.fetch` to an MCP client:

```typescript
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const mcp = company.apis.find((api) => api.type === "mcp");
const transport = new StreamableHTTPClientTransport(new URL(mcp.url), {
  fetch: (url, init) => session.fetch(url, init),
});
const client = new Client({ name: "my-agent", version: "1.0.0" });
await client.connect(transport);
```

## Joining a browser

When your agent browses the Company's website, it joins its browser to the Session, so the website sees the same Session as the APIs (spec 6). The access token never passes through the browser.

```mermaid
sequenceDiagram
    autonumber
    participant SDK as Poppy SDK
    participant Browser as Your agent's browser
    participant Site as Company website

    SDK->>Browser: open(browser_session_endpoint)
    Browser->>Site: GET the browser-session page
    Site-->>Browser: form with a one-time code, plus a join cookie
    SDK->>Browser: readCode()
    SDK->>Site: POST {endpoint}/authorize with code,<br/>Session JWT and access token
    Site-->>SDK: 204
    SDK->>Browser: submit()
    Browser->>Site: POST the form with code and join cookie
    Site-->>Browser: Session cookie, redirect into the site
```

`session.joinBrowser()` runs these steps with a `BrowserJoiner` you implement for your browser, such as Playwright. Join only your agent's own browser, never the User's. Join again after signing in or out, so the website matches.

### Website pages without a browser

From 0.4 an agent may read a page of the Company's website with its own HTTP client rather than a browser — a help article, say — and `session.fetchPage(url)` does it (spec 5.2). The request carries the Session header so the Company can tell which agent and Session it is from, and **never** an access token, so it is signed out even when a browser joined to the same Session is signed in. The header goes only to HTTPS URLs whose host is exactly `organization.domain`; a redirect that leaves that host is followed without it. If a page answers `invalid_session`, the page is fetched once more without the header, which is the only case where leaving it out is allowed (spec 5.6).

On 0.3 no header is sent at all, since that version has website pages carry none. A headless browser is a browser, so it joins through `session.joinBrowser()` instead.

## Conversations

`session.conversations()` talks with the Company Agent (spec 8). A conversation is a list of events: messages from both sides, state changes, and requests from the Company.

```mermaid
sequenceDiagram
    autonumber
    participant SDK as Poppy SDK
    participant CA as Company Agent

    SDK->>CA: POST {endpoint} first message, with a request id
    CA-->>SDK: 201 conversation_id
    SDK->>CA: GET {endpoint}/{id}/events (SSE or long poll)
    CA-->>SDK: message events, text-delta pieces, working false
    CA-->>SDK: authorization event: scopes needed
    Note over SDK: sign in, then continue with the access token
    SDK->>CA: POST {endpoint}/{id}/messages
    CA-->>SDK: user_requested event: wants the User
    SDK->>CA: POST {endpoint} with parent_conversation_id<br/>and user_requested_event_id (Direct Conversation)
    SDK->>CA: POST {endpoint}/{id}/handoff
    CA-->>SDK: handoff pending, then responder human
    SDK->>CA: POST {endpoint}/{id}/close
```

- `conversation.stream()` reads events as server-sent events, reconnecting with `Last-Event-ID`, and falls back to long polling for Companies that don't stream.
- Events are handled in order and never twice. Save `conversation.id`, `cursor` and `handledEventIds` to resume in another Session with `conversations.resume()`.
- `conversation.state` reports `working`, `handoff`, `responder` and `closed` on both versions; on 0.3 they're derived from `status`, which is still there as a getter. Read until `working` is false to get the Company's whole reply, and before closing, since from 0.4 a close doesn't wait its turn (spec 8.7, 8.12).
- To retry a request after a failure, send it again with the same `id`: on 0.3 that is the message's ID, and from 0.4 the request's, which the message takes as its own. The Company won't act on it twice. Each of `send()`, `handoff()`, `cancelHandoff()` and `close()` takes one.
- `conversation.cancelHandoff()` withdraws a request for a person, from 0.4. The Company may stop looking or keep looking, so read `handoff` and `responder` for the outcome rather than depending on the cancel (spec 8.9).
- `author.type` is `human` only for the User's own words, and is the default in Direct Conversations.
- To accept a `user_requested` event, you can call `conversation.openDirect(message, { userRequestedEventId })`. The message is optional. Without one, the Company speaks first (spec 8.10).
- Content that an extension defines travels in a message's `extensions` (spec 8.4). The SDK reads `message.operation` from the Operations extension, `message.links` from the Links extension, and `message.disclosures` from the Disclosures extension. Links and disclosures are Company content, so you decide whether and how to show them. Showing each link's domain helps the User see where it goes.

## Operations

With the Operations extension, a Company asks for the User's approval of exact terms before an action such as an exchange or a payment. Your agent lists `operations` version `2` in `extensions` on the `PoppyAgent`, and, on 0.3, in its client metadata document. From 0.4 it is declared per request in `Poppy-Extensions` instead, which the SDK sends for you.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Your agent
    participant SDK as Poppy SDK
    participant API as Company API

    App->>SDK: session.fetch(POST /exchanges)
    SDK->>API: request
    API-->>SDK: 403 approval_required + operation
    App->>App: operationFromResponse(response)
    App->>User: Company name and renderSummary(summary)
    User-->>App: approves this revision
    App->>SDK: session.fetch(same request, { approval })
    SDK->>API: same request + Poppy-Approval header
    API-->>SDK: 201, performed once
```

- The Company performs only what the approved revision describes, and at most once. A retry with the same approval never performs it twice.
- `renderSummary()` renders only emphasis, paragraphs and lists, and shows links, images and HTML as text, so a summary can't send the User elsewhere.
- In MCP, read the operation with `operationFromToolResult()` and send `approvalMeta()` in the tool call's `_meta`. In a conversation, it arrives on a Company message as `message.operation`, from `extensions.operations`, and you send `approval` on your next message. The SDK sends it in `extensions.operations`, and only to a Company that lists the Operations extension, version 2.
- Text from the Company is never the User's approval. Only your own interface collects it.
