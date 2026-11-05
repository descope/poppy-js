import {
  ES256,
  ecPublicJwk,
  es256Signer,
  type EcPublicJwk,
  nowSeconds,
  randomId,
  sha256,
  type Signer,
  signJwt,
  thumbprint,
} from "./jose.ts";

/** Spec 5.2: a delegation lasts at most 24 hours. */
export const MAX_DELEGATION_LIFETIME = 24 * 60 * 60;
/** Renew a delegation this long before it expires, so the Company never sees an expired one. */
const RENEW_MARGIN = 5 * 60;

interface Delegated {
  privateKey: CryptoKey;
  kid: string;
  delegation: string;
  exp: number;
}

/**
 * The delegated keys of one User ID (spec 5.2). Each key signs only this User ID's Session JWTs, so
 * Companies can't match the User across Companies by key, and a leaked key exposes only this User at one
 * Company (spec 10.7). Keys live only in memory: Companies must not expect them to stay the same.
 */
export class DelegatedKeys {
  readonly #clientId: string;
  readonly #signer: Signer;
  readonly #lifetime: number;
  #current: Promise<Delegated> | undefined;

  constructor(clientId: string, signer: Signer, lifetime: number) {
    this.#clientId = clientId;
    this.#signer = signer;
    this.#lifetime = Math.min(Math.max(lifetime, RENEW_MARGIN * 2), MAX_DELEGATION_LIFETIME);
  }

  async current(): Promise<Delegated> {
    const existing = await this.#current?.catch(() => undefined);
    if (existing !== undefined && nowSeconds() < existing.exp - RENEW_MARGIN) return existing;
    this.#current = this.#issue();
    return this.#current;
  }

  async #issue(): Promise<Delegated> {
    const pair = await crypto.subtle.generateKey(ES256, false, ["sign", "verify"]);
    const jwk: EcPublicJwk = await ecPublicJwk(pair.publicKey);
    const iat = nowSeconds();
    const exp = iat + this.#lifetime;
    // Names no User or Company, so the signer of the delegation learns neither (spec 5.2).
    const delegation = await signJwt(
      { typ: "poppy-delegation+jwt", kid: this.#signer.kid },
      { iss: this.#clientId, cnf: { jwk }, iat, exp, jti: randomId() },
      this.#signer,
    );
    return { privateKey: pair.privateKey, kid: await thumbprint(jwk), delegation, exp };
  }
}

export interface SessionClaims {
  clientId: string;
  /** The Company's identifier (spec 3.2). */
  audience: string;
  sid: string;
  userId: string;
  agentId: string | undefined;
  method: string;
  url: URL;
  accessToken: string | undefined;
}

/** Signs a fresh Session JWT for one request (spec 5.2). */
export async function signSessionJwt(keys: DelegatedKeys, claims: SessionClaims): Promise<string> {
  const key = await keys.current();
  const iat = nowSeconds();
  const payload: Record<string, unknown> = {
    iss: claims.clientId,
    aud: claims.audience,
    sid: claims.sid,
    sub: claims.userId,
    ...(claims.agentId === undefined ? {} : { agent_id: claims.agentId }),
    htm: claims.method.toUpperCase(),
    // Without the query or fragment (RFC 9449 section 4.2).
    htu: `${claims.url.origin}${claims.url.pathname}`,
    iat,
    jti: randomId(),
  };
  if (claims.accessToken !== undefined) payload["ath"] = await sha256(claims.accessToken);
  return signJwt(
    { typ: "poppy-session+jwt", kid: key.kid, poppy_dlg: key.delegation },
    payload,
    es256Signer(key.privateKey),
  );
}
