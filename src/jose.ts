const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function base64url(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString(
    "base64url",
  );
}

/** 128 random bits, base64url: unguessable, and only characters IDs may use (spec 8.2). */
export function randomId(prefix = ""): string {
  return `${prefix}${base64url(crypto.getRandomValues(new Uint8Array(16)))}`;
}

export async function sha256(value: string): Promise<string> {
  return base64url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export const ES256: EcKeyImportParams & EcdsaParams = {
  name: "ECDSA",
  namedCurve: "P-256",
  hash: "SHA-256",
};

/** `alg` values Companies accept for client assertions and delegations (spec 4.1, 5.2). */
export type SigningAlgorithm = "ES256" | "PS384";

/**
 * Signs client assertions and delegations with a key from the agent's `jwks_uri` (spec 4.1, 5.2).
 * Implement it yourself to keep the key in an HSM or KMS, or to have it sign blindly with RFC 9474
 * RSABSSA-SHA384-PSS-Deterministic, which yields `PS384` signatures (spec 10.7).
 */
export interface Signer {
  /** The key's `kid` in the published key set. */
  readonly kid: string;
  readonly alg: SigningAlgorithm;
  /** Returns the JWS signature over `input`: raw `r || s` for ES256, the PSS signature for PS384. */
  sign(input: Uint8Array<ArrayBuffer>): Promise<Uint8Array>;
}

/** A WebCrypto private key from the agent's key set: ECDSA P-256 (ES256) or RSA-PSS SHA-384 (PS384). */
export interface SigningKey {
  privateKey: CryptoKey;
  /** Must match this key's `kid` in the published key set. */
  kid: string;
}

export function signerFromKey({ privateKey, kid }: SigningKey): Signer {
  const name = privateKey.algorithm.name;
  if (name === "ECDSA") {
    return {
      kid,
      alg: "ES256",
      sign: async (input) => new Uint8Array(await crypto.subtle.sign(ES256, privateKey, input)),
    };
  }
  if (name === "RSA-PSS") {
    return {
      kid,
      alg: "PS384",
      // PS384 uses a salt as long as the hash (RFC 7518 section 3.5).
      sign: async (input) =>
        new Uint8Array(
          await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 48 }, privateKey, input),
        ),
    };
  }
  throw new TypeError(`signing key must be ECDSA P-256 or RSA-PSS, not ${name}`);
}

function encodePart(value: Record<string, unknown>): string {
  return base64url(encoder.encode(JSON.stringify(value)));
}

export async function signJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signer: Pick<Signer, "alg" | "sign">,
): Promise<string> {
  const input = `${encodePart({ ...header, alg: signer.alg })}.${encodePart(payload)}`;
  return `${input}.${base64url(await signer.sign(encoder.encode(input)))}`;
}

/** An ES256 signer for a private key that never leaves this process. */
export function es256Signer(privateKey: CryptoKey): Pick<Signer, "alg" | "sign"> {
  return {
    alg: "ES256",
    sign: async (input) => new Uint8Array(await crypto.subtle.sign(ES256, privateKey, input)),
  };
}

export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export async function ecPublicJwk(key: CryptoKey): Promise<EcPublicJwk> {
  const { x, y } = await crypto.subtle.exportKey("jwk", key);
  if (x === undefined || y === undefined) throw new TypeError("not an EC public key");
  return { kty: "EC", crv: "P-256", x, y };
}

/** RFC 7638 thumbprint of an EC or RSA public key: required members only, in lexicographic order. */
export async function thumbprint(jwk: JsonWebKey): Promise<string> {
  const members =
    jwk.kty === "EC"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : jwk.kty === "RSA"
        ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
        : jwk.kty === "OKP"
          ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
          : undefined;
  if (members === undefined) throw new TypeError(`unsupported key type ${String(jwk.kty)}`);
  return sha256(JSON.stringify(members));
}

/** Reads a JWT's header and payload without verifying it. */
export function decodeJwt(jwt: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const [header, payload] = jwt.split(".");
  if (header === undefined || payload === undefined) throw new TypeError("not a JWT");
  return {
    header: JSON.parse(decoder.decode(Buffer.from(header, "base64url"))) as Record<string, unknown>,
    payload: JSON.parse(decoder.decode(Buffer.from(payload, "base64url"))) as Record<
      string,
      unknown
    >,
  };
}
