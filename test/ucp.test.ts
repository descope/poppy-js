import { describe, expect, it } from "vitest";
import {
  discoverCompanyUcp,
  discoverUcp,
  intersectCapabilities,
  negotiateUcp,
  PoppyAgent,
  PoppyProtocolError,
  UcpClient,
  UcpError,
  ucpHandoffUrl,
  ucpIdentityScopes,
  ucpMcpArguments,
  ucpPlatformProfile,
} from "../src/index.ts";
import { signerFromKey } from "../src/jose.ts";
import { CLIENT_ID, MockCompany } from "./mock-company.ts";

const PROFILE_URL = "https://agent.example/ucp-profile.json";
const ENDPOINT = "https://example.com/ucp/v1";
const CHECKOUT = "https://ucp.dev/2026-08-25/schemas/shopping/checkout.json";

function businessProfile(version = "2026-08-25") {
  return {
    ucp: {
      version,
      supported_versions: { "2026-04-08": "https://example.com/.well-known/ucp/2026-04-08" },
      services: {
        "dev.ucp.shopping": [
          { version, transport: "rest", endpoint: ENDPOINT },
          { version, transport: "mcp", endpoint: "https://mcp.example.com/mcp" },
        ],
      },
      capabilities: {
        "dev.ucp.shopping.checkout": [
          { version: "2026-04-08", schema: CHECKOUT },
          { version: "2026-08-25", schema: CHECKOUT },
        ],
        "dev.ucp.shopping.discount": [
          { version: "2026-08-25", schema: CHECKOUT, extends: "dev.ucp.shopping.checkout" },
        ],
        "dev.ucp.shopping.fulfillment": [
          { version: "2026-08-25", schema: CHECKOUT, extends: "dev.ucp.shopping.cart" },
        ],
        // A schema off its namespace's authority, which the platform must drop.
        "com.example.loyalty": [
          { version: "2026-08-25", schema: "https://evil.test/loyalty.json" },
        ],
        "dev.ucp.common.identity_linking": [
          {
            version: "2026-08-25",
            schema: CHECKOUT,
            config: {
              scopes: ["dev.ucp.shopping.checkout:manage", "dev.ucp.shopping.order:read"],
            },
          },
        ],
      },
      payment_handlers: {},
    },
    keys: [],
  };
}

const PLATFORM_CAPABILITIES = {
  "dev.ucp.shopping.checkout": [{ version: "2026-08-25" }],
  "dev.ucp.shopping.discount": [{ version: "2026-08-25", extends: "dev.ucp.shopping.checkout" }],
  "dev.ucp.shopping.fulfillment": [{ version: "2026-08-25", extends: "dev.ucp.shopping.cart" }],
  "dev.ucp.common.identity_linking": [{ version: "2026-08-25" }],
};

/** Verifies the RFC 9421 signature labelled `sig1` with the platform's published key. */
async function verifyUcpSignature(
  request: Request,
  body: string,
  key: JsonWebKey,
): Promise<string | undefined> {
  const input = /(?:^|,\s*)sig1=(\(([^)]*)\);keyid="([^"]+)")/.exec(
    request.headers.get("signature-input") ?? "",
  );
  const signature = /(?:^|,\s*)sig1=:([^:]+):/.exec(request.headers.get("signature") ?? "")?.[1];
  if (input === null || signature === undefined) return "no sig1 signature";
  const url = new URL(request.url);
  const names = (input[2] ?? "").split(" ").map((n) => n.replaceAll('"', ""));
  for (const required of ["@method", "@authority", "@path", "ucp-agent"])
    if (!names.includes(required)) return `${required} isn't covered`;
  if (request.method !== "GET" && !names.includes("idempotency-key"))
    return "idempotency-key isn't covered";
  if (body !== "" && !names.includes("content-digest")) return "content-digest isn't covered";
  const value = (name: string) =>
    name === "@method"
      ? request.method
      : name === "@authority"
        ? url.host
        : name === "@path"
          ? url.pathname
          : name === "@query"
            ? url.search
            : (request.headers.get(name) ?? "");
  const base = [
    ...names.map((n) => `"${n}": ${value(n)}`),
    `"@signature-params": ${input[1]}`,
  ].join("\n");
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    key,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    Buffer.from(signature, "base64"),
    new TextEncoder().encode(base),
  );
  return ok ? undefined : "the signature doesn't verify";
}

async function setup(options: { ucpExtension?: boolean } = {}) {
  const mock = await MockCompany.create({
    poppy: (doc) =>
      options.ucpExtension === false
        ? doc
        : {
            ...doc,
            extensions: { ...(doc["extensions"] as object), ucp: { version: "1" } },
          },
  });
  const ucpKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const ucpPublic = { ...(await crypto.subtle.exportKey("jwk", ucpKey.publicKey)), kid: "ucp-1" };
  const platformProfile = ucpPlatformProfile({
    capabilities: PLATFORM_CAPABILITIES,
    keys: [
      {
        kty: "EC",
        crv: "P-256",
        x: String(ucpPublic.x),
        y: String(ucpPublic.y),
        kid: "ucp-1",
        alg: "ES256",
      },
    ],
  });
  const problems: string[] = [];
  const seen: Request[] = [];
  const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.href === "https://example.com/.well-known/ucp") return Response.json(businessProfile());
    if (url.href === "https://example.com/.well-known/ucp/2026-04-08")
      return Response.json(businessProfile("2026-04-08"));
    if (!url.href.startsWith(ENDPOINT)) return mock.fetch(input, init);

    const body = init.body === undefined || init.body === null ? "" : String(init.body);
    const request = new Request(url, {
      method: init.method ?? "GET",
      headers: new Headers(init.headers),
    });
    seen.push(request);
    // What a UCP business checks: the agent's profile, idempotency, the digest and the signature.
    const agent = /^profile="([^"]+)"$/.exec(request.headers.get("ucp-agent") ?? "")?.[1];
    if (agent !== PROFILE_URL) problems.push("UCP-Agent doesn't name the profile");
    if (request.headers.get("request-id") === null) problems.push("no Request-Id");
    if (request.method !== "GET" && (request.headers.get("idempotency-key") ?? "").length < 16)
      problems.push("no Idempotency-Key");
    if (body !== "") {
      const digest = Buffer.from(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)),
      ).toString("base64");
      if (request.headers.get("content-digest") !== `sha-256=:${digest}:`)
        problems.push("Content-Digest is wrong");
    }
    const keys = (platformProfile["keys"] as JsonWebKey[]) ?? [];
    const signatureProblem = await verifyUcpSignature(request, body, keys[0] ?? {});
    if (signatureProblem !== undefined) problems.push(signatureProblem);

    const path = url.pathname.slice(new URL(ENDPOINT).pathname.length);
    const ucp = { version: "2026-08-25", status: "success" };
    if (path === "/checkout-sessions" && request.method === "POST")
      return Response.json(
        {
          ucp,
          id: "chk_1",
          status: "incomplete",
          line_items: JSON.parse(body).line_items,
          currency: "USD",
          totals: [],
          links: [],
        },
        { status: 201 },
      );
    if (path === "/checkout-sessions/chk_1/complete")
      return Response.json({
        ucp,
        id: "chk_1",
        status: "requires_escalation",
        continue_url: "https://example.com/checkout/chk_1",
        messages: [
          {
            type: "error",
            code: "requires_3ds",
            content: "Verify the card.",
            severity: "requires_buyer_input",
          },
        ],
      });
    return Response.json(
      {
        ucp: { version: "2026-08-25", status: "error" },
        messages: [
          {
            type: "error",
            code: "not_found",
            content: "No such checkout.",
            severity: "unrecoverable",
          },
        ],
      },
      { status: 404 },
    );
  }) as typeof fetch;

  const agent = new PoppyAgent({
    clientId: CLIENT_ID,
    signingKey: { privateKey: mock.agentKey.privateKey, kid: "k1" },
    fetch: fetchFn,
  });
  const company = await agent.discover("example.com");
  const user = await agent.user(company, "alice");
  return { mock, fetchFn, ucpKey, platformProfile, problems, seen, user };
}

describe("UCP discovery and negotiation", () => {
  it("reads the business profile and drops capabilities off their authority", async () => {
    const { fetchFn } = await setup();
    const business = await discoverUcp("example.com", { fetch: fetchFn });
    expect(business.version).toBe("2026-08-25");
    expect(business.services["dev.ucp.shopping"]?.map((s) => s.transport)).toEqual(["rest", "mcp"]);
    expect(Object.keys(business.capabilities)).not.toContain("com.example.loyalty");
  });

  it("intersects capabilities and prunes orphaned extensions", async () => {
    const { fetchFn } = await setup();
    const business = await discoverUcp("example.com", { fetch: fetchFn });
    const negotiation = await negotiateUcp(
      business,
      { capabilities: PLATFORM_CAPABILITIES },
      { fetch: fetchFn },
    );
    expect(Object.keys(negotiation.capabilities).sort()).toEqual([
      "dev.ucp.common.identity_linking",
      "dev.ucp.shopping.checkout",
      "dev.ucp.shopping.discount",
    ]);
    expect(negotiation.capabilities["dev.ucp.shopping.checkout"]?.version).toBe("2026-08-25");
    expect(negotiation.restEndpoint).toBe(ENDPOINT);
    expect(ucpIdentityScopes(negotiation)).toEqual(["dev.ucp.shopping.checkout:manage"]);
  });

  it("negotiates an older version through supported_versions, and refuses unknown ones", async () => {
    const { fetchFn } = await setup();
    const business = await discoverUcp("example.com", { fetch: fetchFn });
    const older = await negotiateUcp(
      business,
      {
        version: "2026-04-08",
        capabilities: { "dev.ucp.shopping.checkout": [{ version: "2026-04-08" }] },
      },
      { fetch: fetchFn },
    );
    expect(older.version).toBe("2026-04-08");
    expect(older.capabilities["dev.ucp.shopping.checkout"]?.version).toBe("2026-04-08");
    await expect(
      negotiateUcp(business, { version: "2025-01-01", capabilities: {} }, { fetch: fetchFn }),
    ).rejects.toMatchObject({ error: "version_unsupported" });
  });

  it("refuses a profile served through a redirect", async () => {
    const redirecting = (async () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://other.example/ucp" },
      })) as unknown as typeof fetch;
    await expect(discoverUcp("example.com", { fetch: redirecting })).rejects.toBeInstanceOf(
      PoppyProtocolError,
    );
  });

  it("intersects by exact version", () => {
    expect(
      intersectCapabilities({ a: [{ version: "2026-01-11" }] }, { a: [{ version: "2026-08-25" }] }),
    ).toEqual({});
  });
});

describe("UCP requests", () => {
  it("signs requests the business verifies, and sends the Session header through the UCP extension", async () => {
    const { fetchFn, ucpKey, problems, seen, user } = await setup();
    expect(user.company.ucp).toEqual({
      profileUrl: "https://example.com/.well-known/ucp",
      ask: false,
    });
    const negotiation = await negotiateUcp(
      await discoverCompanyUcp(user.company, { fetch: fetchFn }),
      { capabilities: PLATFORM_CAPABILITIES },
      { fetch: fetchFn },
    );
    const client = new UcpClient({
      negotiation,
      profileUrl: PROFILE_URL,
      signer: signerFromKey({ privateKey: ucpKey.privateKey, kid: "ucp-1" }),
      session: user.session(),
    });
    const checkout = await client.createCheckout({
      line_items: [{ item: { id: "item_123" }, quantity: 2 }],
    });
    expect(checkout).toMatchObject({ id: "chk_1", status: "incomplete" });

    const completed = await client.completeCheckout(
      "chk_1",
      { payment: {} },
      { idempotencyKey: "idem_0123456789abcdef" },
    );
    expect(ucpHandoffUrl(completed)).toBe("https://example.com/checkout/chk_1");

    const error = await client.getCheckout("missing").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(UcpError);
    expect(error).toMatchObject({
      error: "not_found",
      status: 404,
      messages: [{ severity: "unrecoverable" }],
    });

    expect(problems).toEqual([]);
    expect(seen.every((r) => r.headers.has("poppy-session"))).toBe(true);
    expect(seen[1]?.headers.get("idempotency-key")).toBe("idem_0123456789abcdef");
  });

  it("keeps the Session out of UCP at a Company that doesn't list the extension", async () => {
    const { fetchFn, user } = await setup({ ucpExtension: false });
    expect(user.company.ucp).toBeUndefined();
    await expect(discoverCompanyUcp(user.company, { fetch: fetchFn })).rejects.toThrow(
      PoppyProtocolError,
    );
    const negotiation = await negotiateUcp(
      await discoverUcp("example.com", { fetch: fetchFn }),
      { capabilities: PLATFORM_CAPABILITIES },
      { fetch: fetchFn },
    );
    expect(
      () => new UcpClient({ negotiation, profileUrl: PROFILE_URL, session: user.session() }),
    ).toThrow(PoppyProtocolError);
    // The same endpoint isn't a destination for the Session header without the extension (spec 5.2).
    await expect(user.session().fetch(`${ENDPOINT}/carts`)).rejects.toThrow(PoppyProtocolError);
  });

  it("refuses a non-ES256 signer", async () => {
    const { fetchFn } = await setup();
    const negotiation = await negotiateUcp(
      await discoverUcp("example.com", { fetch: fetchFn }),
      { capabilities: PLATFORM_CAPABILITIES },
      { fetch: fetchFn },
    );
    expect(
      () =>
        new UcpClient({
          negotiation,
          profileUrl: PROFILE_URL,
          signer: { kid: "x", alg: "PS384", sign: async () => new Uint8Array() },
        }),
    ).toThrow(PoppyProtocolError);
  });

  it("builds the platform profile and MCP arguments", () => {
    expect(() =>
      ucpPlatformProfile({ capabilities: {}, keys: [{ kty: "EC", kid: "a", d: "secret" }] }),
    ).toThrow(PoppyProtocolError);
    expect(ucpMcpArguments(PROFILE_URL, { id: "chk_1" }, { idempotencyKey: "k" })).toEqual({
      id: "chk_1",
      meta: { "ucp-agent": { profile: PROFILE_URL }, "idempotency-key": "k" },
    });
  });
});

describe("UCP without a Poppy Session", () => {
  it("calls the business directly and reads flat transport errors", async () => {
    const business = {
      url: "https://shop.example/.well-known/ucp",
      version: "2026-08-25",
      supportedVersions: {},
      services: {},
      capabilities: {},
      paymentHandlers: {},
      keys: [],
    };
    const negotiation = {
      business,
      version: "2026-08-25",
      capabilities: {},
      restEndpoint: "https://shop.example/ucp",
      mcpEndpoint: undefined,
    };
    const calls: string[] = [];
    const fetchFn = (async (input: string | URL | Request, init: RequestInit = {}) => {
      calls.push(`${init.method} ${String(input)}`);
      if (String(input).includes("/carts"))
        return Response.json({ ucp: { version: "2026-08-25", status: "success" }, id: "cart_1" });
      return Response.json(
        { code: "profile_unreachable", content: "Couldn't fetch the profile." },
        { status: 424 },
      );
    }) as typeof fetch;
    const client = new UcpClient({ negotiation, profileUrl: PROFILE_URL, fetch: fetchFn });
    expect(await client.createCart({ line_items: [] })).toMatchObject({ id: "cart_1" });
    expect(await client.getCart("cart_1")).toMatchObject({ id: "cart_1" });
    await expect(
      client.searchCatalog({ query: "jacket" }, { query: { limit: "5" } }),
    ).rejects.toMatchObject({
      error: "profile_unreachable",
      status: 424,
      errorDescription: "Couldn't fetch the profile.",
    });
    await expect(client.getOrder("ord_1")).rejects.toBeInstanceOf(UcpError);
    expect(calls).toContain("POST https://shop.example/ucp/catalog/search?limit=5");
    const local = new UcpClient({
      negotiation: { ...negotiation, restEndpoint: "https://127.0.0.1/ucp" },
      profileUrl: PROFILE_URL,
      fetch: fetchFn,
    });
    await expect(local.getOrder("x")).rejects.toBeInstanceOf(PoppyProtocolError);
    expect(
      () =>
        new UcpClient({
          negotiation: { ...negotiation, restEndpoint: undefined },
          profileUrl: PROFILE_URL,
        }),
    ).toThrow(PoppyProtocolError);
  });
});
