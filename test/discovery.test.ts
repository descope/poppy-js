import { describe, expect, it } from "vitest";
import { discover, isAllowedHost, metadataUrl, PoppyProtocolError } from "../src/index.ts";
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

  it("refuses an issuer without ES256 DPoP", async () => {
    const company = await MockCompany.create();
    company.metadata = { ...company.metadata, dpop_signing_alg_values_supported: ["RS256"] };
    await rejects(company, /ES256/);
  });

  it.each(["token_endpoint", "revocation_endpoint", "device_authorization_endpoint"])(
    "refuses metadata without %s",
    async (field) => {
      const company = await MockCompany.create();
      company.metadata = { ...company.metadata, [field]: undefined };
      await rejects(company, new RegExp(field));
    },
  );

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
});
