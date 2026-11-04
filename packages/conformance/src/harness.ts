import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { clientMetadata, jwks } from "@descope/poppy";
import {
  ConformanceCompany,
  type ScenarioDefinition,
  type ScenarioResult,
  scenarioResult,
} from "@descope/poppy/conformance";

/**
 * Runs an agent in any language against the conformance Company. The harness is an HTTPS proxy: the
 * agent reaches the Company's hosts through `HTTPS_PROXY`, and trusts a CA made for this run. The agent
 * learns each scenario from environment variables, and does its steps with its own code.
 */

/** The hosts the Company answers on, plus the test agent's own host. */
const HOSTS = [
  "shop.test",
  "www.shop.test",
  "mcp.shop.test",
  "agent.test",
  "elsewhere.test",
  "evil.test",
];
const AGENT_ORIGIN = "https://agent.test";
const ALGORITHM = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;

x509.cryptoProvider.set(crypto);

function pem(label: string, der: ArrayBuffer): string {
  const base64 = Buffer.from(der)
    .toString("base64")
    .replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${base64.trimEnd()}\n-----END ${label}-----\n`;
}

/** A CA for this run, and a certificate it issues for every test host. */
async function certificates(): Promise<{ caPem: string; certPem: string; keyPem: string }> {
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 24 * 60 * 60_000);
  const caKeys = (await crypto.subtle.generateKey(ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Personal Agent Protocol Conformance CA",
    notBefore,
    notAfter,
    signingAlgorithm: ALGORITHM,
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });
  const keys = (await crypto.subtle.generateKey(ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=shop.test",
    issuer: ca.subject,
    notBefore,
    notAfter,
    signingAlgorithm: ALGORITHM,
    publicKey: keys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.SubjectAlternativeNameExtension([
        ...HOSTS.map((value) => ({ type: "dns" as const, value })),
        { type: "ip", value: "127.0.0.1" },
      ]),
      new x509.BasicConstraintsExtension(false),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });
  return {
    caPem: ca.toString("pem"),
    certPem: leaf.toString("pem"),
    keyPem: pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", keys.privateKey)),
  };
}

/** The identity the harness gives an agent that doesn't bring its own. */
export interface TestIdentity {
  clientId: string;
  redirectUri: string;
  /** The private key as a JWK, with `kid` and `alg`, for the agent to sign with. */
  signingKey: JsonWebKey & { kid: string; alg: string };
  /** The documents served at the client_id and jwks_uri. */
  documents: Record<string, unknown>;
}

async function testIdentity(): Promise<TestIdentity> {
  const pair = (await crypto.subtle.generateKey(ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const clientId = `${AGENT_ORIGIN}/agent.json`;
  const redirectUri = `${AGENT_ORIGIN}/callback`;
  return {
    clientId,
    redirectUri,
    signingKey: {
      ...(await crypto.subtle.exportKey("jwk", pair.privateKey)),
      kid: "conformance-1",
      alg: "ES256",
    },
    documents: {
      [clientId]: clientMetadata({
        clientId,
        clientName: "Conformance Test Agent",
        jwksUri: `${AGENT_ORIGIN}/jwks.json`,
        redirectUris: [redirectUri],
        extensions: { operations: { version: "2" } },
      }),
      [`${AGENT_ORIGIN}/jwks.json`]: await jwks([
        { publicKey: pair.publicKey, kid: "conformance-1" },
      ]),
    },
  };
}

/** What the agent process gets in `POPPY_CONFORMANCE_CONTEXT`. */
export interface AgentContext {
  protocol_version: "0.3";
  scenario: string;
  website: string;
  steps: ScenarioDefinition["steps"];
  /** The client_id to use. */
  client_id: string;
  /** Where Direct Sign-In returns, one of the client's redirect_uris. */
  redirect_uri: string;
  /** The private JWK to sign with, when the harness provides the identity. */
  signing_key?: JsonWebKey & { kid: string; alg: string };
  /** Your own ID for the User the steps act for. */
  user_id: string;
}

export interface HarnessOptions {
  /**
   * Your agent's own published client_id. Without it, the harness makes a test identity, serves it at
   * https://agent.test, and passes the private key in the context, and the identity checks are skipped.
   */
  clientId?: string;
  /** Your agent's redirect URI, with `clientId`. */
  redirectUri?: string;
}

export interface ScenarioRun {
  result: ScenarioResult;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export class Harness {
  readonly #options: HarnessOptions;
  #company: ConformanceCompany | undefined;
  #identity: TestIdentity | undefined;
  #proxy: http.Server | undefined;
  #caFile = "";
  #port = 0;

  constructor(options: HarnessOptions = {}) {
    this.#options = options;
  }

  /** Starts the proxy and writes the CA to a temporary file. */
  async start(): Promise<void> {
    const { caPem, certPem, keyPem } = await certificates();
    const dir = mkdtempSync(join(tmpdir(), "poppy-conformance-"));
    this.#caFile = join(dir, "ca.pem");
    writeFileSync(this.#caFile, caPem);
    if (this.#options.clientId === undefined) this.#identity = await testIdentity();

    const secureContext = tls.createSecureContext({ cert: certPem, key: keyPem });
    const inner = http.createServer((req, res) => void this.#serve(req, res));
    const proxy = http.createServer((req, res) => {
      // Plain HTTP through the proxy: the protocol allows HTTPS only.
      this.#company?.fail("http.redirects", `sent a plain HTTP request to ${req.url ?? ""}`);
      res.writeHead(400).end();
    });
    proxy.on("connect", (req, socket: import("node:net").Socket, head) => {
      const target = req.url ?? "";
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      const secure = new tls.TLSSocket(socket, { isServer: true, secureContext });
      if (head.length > 0) secure.unshift(head);
      (secure as tls.TLSSocket & { connectTarget?: string }).connectTarget = target;
      inner.emit("connection", secure);
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const address = proxy.address();
    this.#port = typeof address === "object" && address !== null ? address.port : 0;
    this.#proxy = proxy;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.#proxy?.closeAllConnections();
      this.#proxy?.close(() => resolve());
    });
  }

  /** Answers one request that came through the proxy. */
  async #serve(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const target = (req.socket as tls.TLSSocket & { connectTarget?: string }).connectTarget ?? "";
    const host = (req.headers.host ?? target).replace(/:443$/, "");
    const url = new URL(req.url ?? "/", `https://${host}`);
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const body = Buffer.concat(chunks).toString("utf8");
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers))
      if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(", ") : value);
    let response: Response;
    const document = this.#identity?.documents[url.href];
    if (url.origin === AGENT_ORIGIN && this.#identity !== undefined) {
      response =
        document === undefined ? new Response(null, { status: 404 }) : Response.json(document);
    } else if (this.#company !== undefined) {
      response = await this.#company.fetch(url, {
        method: req.method ?? "GET",
        headers,
        ...(body === "" ? {} : { body }),
      });
    } else {
      response = new Response(null, { status: 503 });
    }
    const out: Record<string, string | string[]> = {};
    response.headers.forEach((value, key) => {
      if (key !== "set-cookie") out[key] = value;
    });
    const cookies = response.headers.getSetCookie();
    if (cookies.length > 0) out["set-cookie"] = cookies;
    res.writeHead(response.status, out);
    res.end(Buffer.from(await response.arrayBuffer()));
  }

  /** The documents and keys a Company fetches from the agent's client_id. */
  #agentFetch(): typeof fetch {
    const identity = this.#identity;
    if (identity === undefined) return fetch;
    return (async (input: string | URL | Request) => {
      const body = identity.documents[String(input instanceof Request ? input.url : input)];
      return body === undefined ? new Response(null, { status: 404 }) : Response.json(body);
    }) as typeof fetch;
  }

  /** The environment that points an agent at the harness, in any language. */
  environment(definition: ScenarioDefinition): Record<string, string> {
    const proxy = `http://127.0.0.1:${this.#port}`;
    const context: AgentContext = {
      protocol_version: "0.3",
      scenario: definition.name,
      website: "https://www.shop.test",
      steps: definition.steps,
      client_id: this.#options.clientId ?? this.#identity?.clientId ?? "",
      redirect_uri: this.#options.redirectUri ?? this.#identity?.redirectUri ?? "",
      ...(this.#identity === undefined ? {} : { signing_key: this.#identity.signingKey }),
      user_id: "conformance-user",
    };
    return {
      POPPY_CONFORMANCE_SCENARIO: definition.name,
      POPPY_CONFORMANCE_CONTEXT: JSON.stringify(context),
      HTTPS_PROXY: proxy,
      https_proxy: proxy,
      HTTP_PROXY: proxy,
      http_proxy: proxy,
      NO_PROXY: "",
      no_proxy: "",
      // Node's fetch uses the proxy only when asked (Node 24).
      NODE_USE_ENV_PROXY: "1",
      NODE_EXTRA_CA_CERTS: this.#caFile,
      SSL_CERT_FILE: this.#caFile,
      REQUESTS_CA_BUNDLE: this.#caFile,
      CURL_CA_BUNDLE: this.#caFile,
    };
  }

  /** Runs `command` once for a scenario, with the website appended, and judges what it sent. */
  async run(
    definition: ScenarioDefinition,
    command: string,
    options: { timeoutMs?: number } = {},
  ): Promise<ScenarioRun> {
    const company = new ConformanceCompany(definition.company, { agentFetch: this.#agentFetch() });
    this.#company = company;
    const child = spawn(`${command} https://www.shop.test`, {
      shell: true,
      env: { ...process.env, ...this.environment(definition) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, options.timeoutMs ?? 30_000);
    const exitCode = await new Promise<number | null>((resolve) => child.on("close", resolve));
    clearTimeout(timer);
    this.#company = undefined;
    const stepErrors = stdout.split("\n").flatMap((line) => {
      try {
        const parsed = JSON.parse(line) as { step?: unknown; error?: unknown };
        return typeof parsed.error === "string" ? [`${String(parsed.step)}: ${parsed.error}`] : [];
      } catch {
        return [];
      }
    });
    if (timedOut)
      stepErrors.push(`the agent didn't finish within ${options.timeoutMs ?? 30_000} ms`);
    // With the harness's own identity, the identity checks test the harness, not the agent.
    if (this.#identity !== undefined) {
      company.skip("identity.metadata");
      company.skip("identity.public-keys");
    }
    return {
      result: scenarioResult(definition, company, stepErrors),
      exitCode,
      stdout,
      stderr,
      timedOut,
    };
  }
}
