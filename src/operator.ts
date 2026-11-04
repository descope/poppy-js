import { nowSeconds, randomId, thumbprint } from "./jose.ts";

/**
 * Signs requests that carry the Session header with an HTTP Message Signature (RFC 9421) in the Web Bot
 * Auth profile, so a Company's bot defenses can recognize the operator (spec 5.3). The signature covers
 * `poppy-session`, and `authorization` when present. On a UCP request, it also covers the request target
 * and UCP's headers, so one signature serves both protocols (UCP extension 4). It is compatibility support:
 * it never replaces the Session JWT.
 */
export interface OperatorSignatureOptions {
  /** An Ed25519 private key. Publish its public key in your Web Bot Auth key directory. */
  privateKey: CryptoKey;
  /** The key's JWK thumbprint; see {@link operatorKeyId}. */
  keyId: string;
  /** URL of your key directory, sent in `Signature-Agent` and covered by the signature. */
  signatureAgent?: string;
  /** Seconds the signature is valid. Defaults to 60. */
  lifetime?: number;
}

/** The RFC 7638 thumbprint Web Bot Auth uses as `keyid`, from an Ed25519 public key. */
export async function operatorKeyId(publicKey: CryptoKey): Promise<string> {
  return thumbprint(await crypto.subtle.exportKey("jwk", publicKey));
}

const encoder = new TextEncoder();

function quote(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/** Adds `Signature-Input`, `Signature` and, if configured, `Signature-Agent` to `headers`. */
export async function signOperator(
  options: OperatorSignatureOptions,
  url: URL,
  headers: Headers,
  method?: string,
): Promise<void> {
  if (options.signatureAgent !== undefined)
    headers.set("signature-agent", quote(options.signatureAgent));
  // RFC 9421 section 2.2.3: the host, and the port only when it is not the default.
  const components: [string, string][] = [["@authority", url.host.toLowerCase()]];
  const ucp = headers.has("ucp-agent");
  if (ucp) {
    components.push(["@method", (method ?? "GET").toUpperCase()], ["@path", url.pathname]);
    if (url.search !== "") components.push(["@query", url.search]);
  }
  const names = ["poppy-session", "authorization", "signature-agent"];
  if (ucp) names.push("content-digest", "content-type", "ucp-agent", "idempotency-key");
  for (const name of names) {
    const value = headers.get(name);
    if (value !== null) components.push([name, value.trim()]);
  }
  const created = nowSeconds();
  const params =
    `(${components.map(([name]) => quote(name)).join(" ")})` +
    `;created=${created};expires=${created + (options.lifetime ?? 60)}` +
    `;keyid=${quote(options.keyId)};alg="ed25519";nonce=${quote(randomId())};tag="web-bot-auth"`;
  const base = [
    ...components.map(([name, value]) => `${quote(name)}: ${value}`),
    `"@signature-params": ${params}`,
  ].join("\n");
  const signature = await crypto.subtle.sign("Ed25519", options.privateKey, encoder.encode(base));
  addSignature(headers, "sig1", params, signature);
}

/**
 * Adds a signature to `Signature-Input` and `Signature`, beside any already there, such as a UCP request
 * signature (RFC 9421 section 4: both headers are Dictionaries). Takes the next free label after `label`.
 */
export function addSignature(
  headers: Headers,
  label: string,
  params: string,
  signature: ArrayBuffer | Uint8Array,
): string {
  const existing = headers.get("signature-input");
  const taken = new Set(
    (existing ?? "").split(",").map((member) => member.trim().split("=")[0] ?? ""),
  );
  let name = label;
  for (let n = 2; taken.has(name); n++) name = `${label.replace(/\d+$/, "")}${n}`;
  const value = Buffer.from(
    signature instanceof Uint8Array ? signature : new Uint8Array(signature),
  );
  const append = (header: string, member: string) => {
    const current = headers.get(header);
    headers.set(header, current === null ? member : `${current}, ${member}`);
  };
  append("signature-input", `${name}=${params}`);
  append("signature", `${name}=:${value.toString("base64")}:`);
  return name;
}
