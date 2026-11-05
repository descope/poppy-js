import { PoppyProtocolError } from "./errors.ts";

export type Fetch = typeof fetch;

const MAX_REDIRECTS = 5;

export function httpsUrl(value: unknown, what: string): URL {
  if (typeof value !== "string") throw new PoppyProtocolError(`${what} is missing`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new PoppyProtocolError(`${what} is not a URL`);
  }
  if (url.protocol !== "https:") throw new PoppyProtocolError(`${what} must use https`);
  if (url.username !== "" || url.password !== "")
    throw new PoppyProtocolError(`${what} must not contain credentials`);
  return url;
}

function isPrivateIpv4([a = 0, b = 0]: number[]): boolean {
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

/**
 * Loopback, private, shared (100.64/10), link-local and site-local addresses and `localhost` (spec 3).
 * Takes a WHATWG URL hostname, which is already normalized (`0x7f.1` becomes `127.0.0.1`,
 * `::ffff:127.0.0.1` becomes `[::ffff:7f00:1]`).
 * ponytail: checks the name only; a DNS name that resolves to a private address is not caught.
 */
export function isPrivateHost(hostname: string): boolean {
  const host = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (/^[\d.]+$/.test(host)) return isPrivateIpv4(host.split(".").map(Number));
  // An IPv4 address inside IPv6: mapped, translated, compatible, NAT64 (64:ff9b::/96) and 6to4 (2002::/16).
  const embedded =
    /^(?:::(?:ffff:(?:0:)?)?|64:ff9b::)([\da-f]{1,4}):[\da-f]{1,4}$/.exec(host) ??
    /^2002:([\da-f]{1,4})(?::|$)/.exec(host);
  if (embedded !== null) {
    const high = Number.parseInt(embedded[1] ?? "", 16);
    return isPrivateIpv4([high >> 8, high & 0xff]);
  }
  return (
    host === "::" ||
    host === "::1" ||
    host.startsWith("64:ff9b:1:") ||
    /^f[cd][\da-f]{2}:/.test(host) ||
    /^fe[89a-f][\da-f]:/.test(host)
  );
}

/** Refuses a private address unless `allowPrivate` (spec 3). */
export function checkPublicHost(url: URL, what: string, allowPrivate: boolean): void {
  if (!allowPrivate && isPrivateHost(url.hostname)) {
    throw new PoppyProtocolError(`${what} host ${url.hostname} is a private address`);
  }
}

export interface JsonResult {
  status: number;
  body: unknown;
  /** The URL that answered, after redirects. */
  url: URL;
}

/**
 * GETs a public JSON document with no credentials. Follows up to five redirects, each of which must stay
 * on https and off private addresses (spec 3). Returns 404 as `{ status: 404 }` when `allowNotFound`, and
 * throws on any other error status.
 */
export async function getJson(
  fetchFn: Fetch,
  url: URL,
  what: string,
  options: { allowPrivate?: boolean; allowNotFound?: boolean; followRedirects?: boolean } = {},
): Promise<JsonResult> {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    checkPublicHost(current, what, options.allowPrivate ?? false);
    const response = await fetchFn(current, {
      redirect: "manual",
      headers: { accept: "application/json" },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (options.followRedirects === false)
        throw new PoppyProtocolError(`${what} must not redirect`);
      if (location === null) throw new PoppyProtocolError(`${what} redirect has no Location`);
      current = httpsUrl(new URL(location, current).href, `${what} redirect`);
      continue;
    }
    if (response.status === 404 && options.allowNotFound) {
      await response.body?.cancel();
      return { status: 404, body: undefined, url: current };
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new PoppyProtocolError(`${what} returned HTTP ${response.status}`);
    }
    try {
      return { status: response.status, body: await response.json(), url: current };
    } catch {
      throw new PoppyProtocolError(`${what} is not JSON`);
    }
  }
  throw new PoppyProtocolError(`${what} redirected more than ${MAX_REDIRECTS} times`);
}

/** Like {@link getJson}, but returns the body as text, for documents that may be YAML. */
export async function getText(
  fetchFn: Fetch,
  url: URL,
  what: string,
  allowPrivate: boolean,
): Promise<string> {
  return new TextDecoder().decode(await getBytes(fetchFn, url, what, allowPrivate));
}

/** Like {@link getJson}, but returns the body's raw bytes, such as a skill artifact to hash. */
export async function getBytes(
  fetchFn: Fetch,
  url: URL,
  what: string,
  allowPrivate: boolean,
): Promise<Uint8Array> {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    checkPublicHost(current, what, allowPrivate);
    const response = await fetchFn(current, { redirect: "manual" });
    if (isRedirect(response)) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (location === null) throw new PoppyProtocolError(`${what} redirect has no Location`);
      current = httpsUrl(new URL(location, current).href, `${what} redirect`);
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new PoppyProtocolError(`${what} returned HTTP ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }
  throw new PoppyProtocolError(`${what} redirected more than ${MAX_REDIRECTS} times`);
}

/** Never follows redirects, so credentials in the body stay at their endpoint (spec 3). */
export function postForm(
  fetchFn: Fetch,
  url: string,
  body: URLSearchParams,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetchFn(url, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
      ...headers,
    },
    body,
  });
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isRedirect(response: Response): boolean {
  return response.status >= 300 && response.status < 400;
}

/** `https://{host}` for a domain, lowercased with no trailing slash (spec 3.2). */
export function originOf(domain: string): string {
  return `https://${domain.toLowerCase()}`;
}

/**
 * The RFC 9728 section 3.1 metadata URL for a resource: the well-known suffix goes between the host and
 * the path, and a lone `/` path is dropped.
 */
export function resourceMetadataUrl(resource: string): URL {
  const url = new URL(resource);
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return new URL(`${url.origin}/.well-known/oauth-protected-resource${path}`);
}

/** RFC 8414 section 3.1: the same rule for an issuer. */
export function authorizationServerMetadataUrl(issuer: string): URL {
  const url = new URL(issuer);
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return new URL(`${url.origin}/.well-known/oauth-authorization-server${path}`);
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      reject(signal?.reason);
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
