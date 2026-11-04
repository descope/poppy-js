import { describe, expect, it } from "vitest";
import {
  approvalHeader,
  approvalMeta,
  clientMetadata,
  isOperationExpired,
  jwks,
  operationFromToolResult,
  operatorKeyId,
  parseChallenges,
  parseEvent,
  PoppyProtocolError,
  renderSummary,
} from "../src/index.ts";
import { isPrivateHost } from "../src/http.ts";
import { signOperator } from "../src/operator.ts";
import { DelegatedKeys, MAX_DELEGATION_LIFETIME, signSessionJwt } from "../src/session-jwt.ts";
import { decodeJwt, signerFromKey, thumbprint } from "../src/jose.ts";

describe("WWW-Authenticate", () => {
  it("parses several challenges and quoted values", () => {
    const [bearer, dpop] = parseChallenges(
      'Bearer error="insufficient_scope", scope="orders:read orders:write", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", DPoP algs="ES256", error=invalid_token',
    );
    expect(bearer).toMatchObject({
      scheme: "bearer",
      error: "insufficient_scope",
      scope: "orders:read orders:write",
      resourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    });
    expect(dpop).toMatchObject({
      scheme: "dpop",
      error: "invalid_token",
      params: { algs: "ES256" },
    });
  });

  it("reads extension_required and escaped quotes", () => {
    const [challenge] = parseChallenges(
      'Bearer error="extension_required", extension="operations", error_description="say \\"hi\\""',
    );
    expect(challenge?.extension).toBe("operations");
    expect(challenge?.params["error_description"]).toBe('say "hi"');
  });

  it("handles a bare scheme", () => {
    expect(parseChallenges("Bearer")).toEqual([
      expect.objectContaining({ scheme: "bearer", error: undefined, scope: undefined }),
    ]);
    expect(parseChallenges(null)).toEqual([]);
  });
});

describe("operations", () => {
  it("renders only emphasis, paragraphs and lists, escaping everything else", () => {
    expect(
      renderSummary(
        "Pay **$70**.\n\n- Item *one*\n- Item two\n\n<img src=x onerror=alert(1)> ![x](https://e.test/x.png)",
      ),
    ).toBe(
      "<p>Pay <strong>$70</strong>.</p><ul><li>Item <em>one</em></li><li>Item two</li></ul>" +
        "<p>&lt;img src=x onerror=alert(1)&gt; ![x](https://e.test/x.png)</p>",
    );
    expect(renderSummary("1. First\n2. Second")).toBe("<ol><li>First</li><li>Second</li></ol>");
  });

  it("serializes approvals for APIs and MCP", () => {
    const approval = { operationId: "exc_5Rt2", revision: "1791487200-k3Jd9Qx2mW8v" };
    expect(approvalHeader(approval)).toBe(
      'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v"',
    );
    expect(approvalMeta(approval)).toEqual({
      "personalagentprotocol.org/approval": {
        operation_id: "exc_5Rt2",
        revision: "1791487200-k3Jd9Qx2mW8v",
      },
    });
    expect(() => approvalHeader({ operationId: 'a", b="c', revision: "r" })).toThrow(
      PoppyProtocolError,
    );
  });

  it("reads an operation from an MCP tool error", () => {
    const operation = operationFromToolResult({
      isError: true,
      content: [{ type: "text", text: "Not done yet." }],
      structuredContent: {
        operation: {
          operation_id: "exc_1",
          revision: "r1",
          summary: "Do it.",
          expires_at: "2000-01-01T00:00:00Z",
        },
      },
    });
    expect(operation?.operationId).toBe("exc_1");
    expect(operation !== undefined && isOperationExpired(operation)).toBe(true);
    expect(operationFromToolResult({ isError: false })).toBeUndefined();
  });
});

describe("client metadata", () => {
  it("builds the document with redirect URIs and extensions", () => {
    expect(
      clientMetadata({
        clientId: "https://agent.example/agent.json",
        clientName: "Agent",
        jwksUri: "https://agent.example/jwks.json",
        redirectUris: ["https://agent.example/callback", "http://127.0.0.1/callback"],
        extensions: { operations: { version: "2" } },
      }),
    ).toEqual({
      client_id: "https://agent.example/agent.json",
      client_name: "Agent",
      jwks_uri: "https://agent.example/jwks.json",
      redirect_uris: ["https://agent.example/callback", "http://127.0.0.1/callback"],
      token_endpoint_auth_method: "private_key_jwt",
      extensions: { operations: { version: "2" } },
    });
  });

  it("refuses URIs on other hosts", () => {
    const base = {
      clientId: "https://agent.example/agent.json",
      clientName: "A",
      jwksUri: "https://agent.example/j",
    };
    expect(() => clientMetadata({ ...base, jwksUri: "https://cdn.example/j" })).toThrow(
      PoppyProtocolError,
    );
    expect(() => clientMetadata({ ...base, redirectUris: ["https://evil.test/cb"] })).toThrow(
      PoppyProtocolError,
    );
    expect(() => clientMetadata({ ...base, redirectUris: ["http://localhost/cb"] })).toThrow(
      PoppyProtocolError,
    );
  });

  it("publishes only public key members for ES256 and PS384 keys", async () => {
    const ec = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const rsa = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-384",
      },
      true,
      ["sign", "verify"],
    );
    const { keys } = await jwks([
      { publicKey: ec.publicKey, kid: "ec" },
      { publicKey: rsa.publicKey, kid: "rsa" },
    ]);
    expect(keys.map((k) => [k.kty, k.alg])).toEqual([
      ["EC", "ES256"],
      ["RSA", "PS384"],
    ]);
    expect(keys.some((k) => "d" in k || "p" in k)).toBe(false);
  });
});

describe("delegated keys", () => {
  it("issue short-lived delegations that name no User or Company", async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const keys = new DelegatedKeys(
      "https://agent.example/agent.json",
      signerFromKey({ privateKey: pair.privateKey, kid: "k1" }),
      10 * MAX_DELEGATION_LIFETIME,
    );
    const jwt = await signSessionJwt(keys, {
      clientId: "https://agent.example/agent.json",
      audience: "https://auth.example.com",
      sid: "sid1",
      userId: "usr_1",
      agentId: "agt_1",
      method: "get",
      url: new URL("https://api.example.com/x?y=1#z"),
      accessToken: undefined,
    });
    const { header, payload } = decodeJwt(jwt);
    expect(header).toMatchObject({ typ: "poppy-session+jwt", alg: "ES256" });
    expect(payload).toMatchObject({
      htm: "GET",
      htu: "https://api.example.com/x",
      agent_id: "agt_1",
    });
    const delegation = decodeJwt(String(header["poppy_dlg"]));
    expect(delegation.header).toMatchObject({
      typ: "poppy-delegation+jwt",
      kid: "k1",
      alg: "ES256",
    });
    const claims = delegation.payload;
    expect(Number(claims["exp"]) - Number(claims["iat"])).toBe(MAX_DELEGATION_LIFETIME);
    expect(Object.keys(claims).sort()).toEqual(["cnf", "exp", "iat", "iss", "jti"]);
    const cnf = (claims["cnf"] as { jwk: JsonWebKey }).jwk;
    expect(header["kid"]).toBe(await thumbprint(cnf));
    expect("d" in cnf).toBe(false);
  });
});

describe("operator signatures", () => {
  it("signs @authority, poppy-session and authorization with Web Bot Auth parameters", async () => {
    const pair = (await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const keyId = await operatorKeyId(pair.publicKey);
    const headers = new Headers({ "poppy-session": "eyJ.a.b", authorization: "Bearer at_1" });
    await signOperator(
      {
        privateKey: pair.privateKey,
        keyId,
        signatureAgent: "https://agent.example/.well-known/http-message-signatures-directory",
      },
      new URL("https://api.example.com:443/orders"),
      headers,
    );
    const input = headers.get("signature-input") ?? "";
    expect(input).toMatch(
      /^sig1=\("@authority" "poppy-session" "authorization" "signature-agent"\);created=\d+;expires=\d+;keyid="[^"]+";alg="ed25519";nonce="[^"]+";tag="web-bot-auth"$/,
    );
    const params = input.slice("sig1=".length);
    const base = [
      '"@authority": api.example.com',
      '"poppy-session": eyJ.a.b',
      '"authorization": Bearer at_1',
      '"signature-agent": "https://agent.example/.well-known/http-message-signatures-directory"',
      `"@signature-params": ${params}`,
    ].join("\n");
    const signature = Buffer.from(
      /^sig1=:(.*):$/.exec(headers.get("signature") ?? "")?.[1] ?? "",
      "base64",
    );
    expect(
      await crypto.subtle.verify(
        "Ed25519",
        pair.publicKey,
        signature,
        new TextEncoder().encode(base),
      ),
    ).toBe(true);
  });
});

describe("conversation events", () => {
  it("skips unknown types and normalizes unknown status and responder", () => {
    expect(parseEvent({ id: "e1", type: "future_thing", created_at: "x" })).toBeUndefined();
    expect(
      parseEvent({ id: "e2", type: "state", status: "paused", responder: "robot" }),
    ).toMatchObject({
      status: "working",
      responder: "human",
    });
    expect(parseEvent({ id: "e3", type: "user_requested", reason: "Confirm" })).toMatchObject({
      reason: "Confirm",
    });
    expect(parseEvent({ id: "e4", type: "direct_opened", conversation_id: "cnv_2" })).toMatchObject(
      {
        conversationId: "cnv_2",
      },
    );
  });
});

describe("addresses", () => {
  it.each([
    ["localhost", true],
    ["127.0.0.1", true],
    ["10.1.2.3", true],
    ["169.254.169.254", true],
    ["[::1]", true],
    ["[::ffff:7f00:1]", true],
    ["[fd00::1]", true],
    ["example.com", false],
    ["8.8.8.8", false],
  ])("%s private: %s", (host, expected) => {
    expect(isPrivateHost(host)).toBe(expected);
  });
});
