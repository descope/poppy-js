import { describe, expect, it } from "vitest";
import { isAllowedHost, metadataUrl } from "../src/discovery.ts";
import { isPrivateHost } from "../src/http.ts";
import { discover, PoppyProtocolError } from "../src/index.ts";
import { ISSUER, METADATA_URL, MockCompany, TOKEN_ENDPOINT, WEBSITE } from "./mock-company.ts";

const POPPY_URL = `${WEBSITE}/.well-known/poppy.json`;

function redirect(location: string): () => Response {
  return () => new Response(null, { status: 302, headers: { location } });
}

async function rejects(company: MockCompany, message: RegExp, website = "example.com") {
  const error = await discover(website, { fetch: company.fetch }).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(PoppyProtocolError);
  expect(String(error)).toMatch(message);
}

describe("metadataUrl", () => {
  it("inserts the well-known suffix between host and issuer path (RFC 8414)", () => {
    expect(metadataUrl(ISSUER).href).toBe(METADATA_URL);
    expect(metadataUrl("https://auth.example.com/").href).toBe(
      "https://auth.example.com/.well-known/oauth-authorization-server",
    );
  });
});

describe("discover", () => {
  it("returns the Company with endpoints from the issuer metadata", async () => {
    const company = await MockCompany.create();
    const result = await discover("example.com", { fetch: company.fetch });
    expect(result).toMatchObject({
      domain: "example.com",
      issuer: ISSUER,
      tokenEndpoint: TOKEN_ENDPOINT,
      deviceScopes: ["poppy:read", "poppy:write"],
      allowedHosts: ["example.com", "api.example.com"],
    });
  });

  it("follows https redirects and checks the final host", async () => {
    const company = await MockCompany.create();
    company.routes.set("https://www.example.com/.well-known/poppy.json", redirect(POPPY_URL));
    const result = await discover("https://www.example.com", { fetch: company.fetch });
    expect(result.domain).toBe("example.com");
  });

  it("matches organization.domain ignoring case only", async () => {
    const company = await MockCompany.create();
    company.poppy = { ...company.poppy, organization: { domain: "Example.COM" } };
    expect((await discover("example.com", { fetch: company.fetch })).domain).toBe("example.com");
  });

  it("skips API types it does not know, without checking them", async () => {
    const company = await MockCompany.create();
    company.poppy = {
      ...company.poppy,
      apis: [
        { type: "graphql", url: "http://other.example.org/graphql" },
        { type: "mcp", url: "https://mcp.example.com/mcp" },
      ],
    };
    const result = await discover("example.com", { fetch: company.fetch });
    expect(result.apis.map((api) => api.type)).toEqual(["mcp"]);
    expect(result.allowedHosts).toEqual(["example.com", "mcp.example.com"]);
  });

  it("refuses a redirect to http", async () => {
    const company = await MockCompany.create();
    company.routes.set(POPPY_URL, redirect("http://example.com/.well-known/poppy.json"));
    await rejects(company, /must use https/);
  });

  it("refuses an http website", async () => {
    await rejects(await MockCompany.create(), /must use https/, "http://example.com");
  });

  it("refuses poppy.json without organization.domain", async () => {
    const company = await MockCompany.create();
    company.poppy = { ...company.poppy, organization: { name: "Example" } };
    await rejects(company, /organization.domain is missing/);
  });

  it("refuses an unsupported major version", async () => {
    const company = await MockCompany.create();
    company.poppy = { ...company.poppy, protocol_version: "1.0" };
    await rejects(company, /not supported/);
  });

  it("refuses a document whose domain is not the host that served it", async () => {
    const company = await MockCompany.create();
    company.routes.set(POPPY_URL, redirect("https://example.org/.well-known/poppy.json"));
    company.routes.set("https://example.org/.well-known/poppy.json", () =>
      Response.json(company.poppy),
    );
    await rejects(company, /does not match the host/);
  });

  it("refuses metadata for another issuer", async () => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, issuer: "https://auth.example.com" };
    await rejects(company, /issuer does not match/);
  });

  it.each([
    ["missing", undefined],
    ["not listing the domain", ["example.org"]],
  ])("refuses poppy_domains %s", async (_, poppyDomains) => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, poppy_domains: poppyDomains };
    await rejects(company, /poppy_domains/);
  });

  it.each([
    [["RS256"], /ES256/],
    [undefined, /dpop_signing_alg_values_supported must be a list/],
  ])("refuses an issuer without ES256 DPoP (%j)", async (algs, message) => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, dpop_signing_alg_values_supported: algs };
    await rejects(company, message);
  });

  it("refuses an http token_endpoint", async () => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, token_endpoint: "http://auth.example.com/token" };
    await rejects(company, /token_endpoint must use https/);
  });

  it.each(["token_endpoint", "revocation_endpoint", "device_authorization_endpoint"])(
    "refuses metadata without %s",
    async (field) => {
      const company = await MockCompany.create();
      company.metadata = { ...company.metadata, [field]: undefined };
      await rejects(company, new RegExp(field));
    },
  );

  it("refuses a private website", async () => {
    await rejects(await MockCompany.create(), /private address/, "localhost");
  });

  it("refuses a redirect to a private address", async () => {
    const company = await MockCompany.create();
    company.routes.set(POPPY_URL, redirect("https://10.0.0.5/.well-known/poppy.json"));
    await rejects(company, /10\.0\.0\.5 is a private address/);
  });

  it.each(["token_endpoint", "revocation_endpoint", "device_authorization_endpoint"])(
    "refuses a %s on a private address",
    async (field) => {
      const company = await MockCompany.create();
      company.metadata = { ...company.metadata, [field]: "https://169.254.169.254/x" };
      await rejects(company, /169\.254\.169\.254 is a private address/);
    },
  );

  it("refuses an API on a private address", async () => {
    const company = await MockCompany.create();
    company.poppy = { ...company.poppy, apis: [{ type: "mcp", url: "https://[::1]/mcp" }] };
    await rejects(company, /private address/);
  });

  it("allows private addresses when asked to", async () => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, token_endpoint: "https://127.0.0.1/token" };
    const result = await discover("example.com", {
      fetch: company.fetch,
      allowPrivateAddresses: true,
    });
    expect(result.tokenEndpoint).toBe("https://127.0.0.1/token");
  });

  it("gives up after five redirects", async () => {
    const company = await MockCompany.create();
    company.routes.set(POPPY_URL, redirect(POPPY_URL));
    await rejects(company, /more than 5/);
  });
});

describe("isAllowedHost", () => {
  it("allows the domain, its subdomains and listed hosts only", async () => {
    const company = await discover("example.com", { fetch: (await MockCompany.create()).fetch });
    expect(isAllowedHost(company, "example.com")).toBe(true);
    expect(isAllowedHost(company, "API.example.com")).toBe(true);
    expect(isAllowedHost(company, "a.b.example.com")).toBe(true);
    expect(isAllowedHost(company, "evilexample.com")).toBe(false);
    expect(isAllowedHost(company, "example.com.evil.org")).toBe(false);
  });

  it("allows other hosts only when poppy.json lists them as an API or poppy endpoint", async () => {
    const mock = await MockCompany.create();
    mock.poppy = {
      ...mock.poppy,
      apis: [
        { type: "openapi", url: "https://api.example.net/openapi.json" },
        { type: "future", url: "http://ignored.example.org" },
      ],
      agent: {
        protocols: [
          { type: "poppy", endpoint: "https://chat.example.io/poppy" },
          { type: "future", endpoint: "http://other.example.org" },
        ],
      },
    };
    const company = await discover("example.com", { fetch: mock.fetch });
    expect(isAllowedHost(company, "api.example.net")).toBe(true);
    expect(isAllowedHost(company, "chat.example.io")).toBe(true);
    expect(isAllowedHost(company, "sub.api.example.net")).toBe(false);
    expect(isAllowedHost(company, "ignored.example.org")).toBe(false);
    expect(isAllowedHost(company, "other.example.org")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  it.each([
    ["https://localhost/", true],
    ["https://localhost./", true],
    ["https://app.localhost/", true],
    ["https://127.0.0.1/", true],
    ["https://0x7f.1/", true],
    ["https://0.0.0.0/", true],
    ["https://10.1.2.3/", true],
    ["https://172.16.0.1/", true],
    ["https://172.31.255.255/", true],
    ["https://192.168.1.1/", true],
    ["https://169.254.169.254/", true],
    ["https://[::]/", true],
    ["https://[::1]/", true],
    ["https://[::ffff:127.0.0.1]/", true],
    ["https://[::ffff:a00:1]/", true],
    ["https://[fd12:3456::1]/", true],
    ["https://[fe80::1]/", true],
    ["https://[fec0::1]/", true],
    ["https://LOCALHOST/", true],
    ["https://100.100.100.200/", true],
    ["https://[::127.0.0.1]/", true],
    ["https://[::ffff:0:7f00:1]/", true],
    ["https://[64:ff9b::a9fe:a9fe]/", true],
    ["https://[2002:7f00:1::]/", true],
    ["https://[2002:a00::]/", true],
    ["https://100.128.0.1/", false],
    ["https://[64:ff9b::808:808]/", false],
    ["https://[2002:808:808::]/", false],
    ["https://172.15.0.1/", false],
    ["https://172.32.0.1/", false],
    ["https://8.8.8.8/", false],
    ["https://[::ffff:808:808]/", false],
    ["https://[fc::1]/", false],
    ["https://[2001:db8::1]/", false],
    ["https://example.com/", false],
    ["https://localhost.example.com/", false],
  ])("%s -> %s", (url, expected) => {
    expect(isPrivateHost(new URL(url).hostname)).toBe(expected);
  });
});
