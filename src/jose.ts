const encoder = new TextEncoder();

export function base64url(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString("base64url");
}

/** A random identifier with 128 bits of entropy (spec 4.2 `jti`). */
export function randomId(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(16)));
}

export async function sha256(value: string): Promise<string> {
  return base64url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export const ES256: EcKeyImportParams & EcdsaParams = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

/** Signs a compact JWS with ES256. WebCrypto already returns the raw r||s signature JWS expects. */
export async function signJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const input = `${base64url(encoder.encode(JSON.stringify({ ...header, alg: "ES256" })))}.${base64url(
    encoder.encode(JSON.stringify(payload)),
  )}`;
  const signature = await crypto.subtle.sign(ES256, privateKey, encoder.encode(input));
  return `${input}.${base64url(signature)}`;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Exports the public half of a P-256 key as a JWK with only public members. */
export async function publicJwk(key: CryptoKey): Promise<JsonWebKey> {
  const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", key);
  return { kty, crv, x, y } as JsonWebKey;
}
