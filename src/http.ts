import { PoppyProtocolError } from "./errors.ts";

/** A `fetch` implementation, such as the global one or a test double. */
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
  return url;
}

/** Fetches a JSON document, following up to five redirects, each of which must stay on https (spec 3). */
export async function getJson(
  fetchFn: Fetch,
  url: URL,
  what: string,
): Promise<{ body: unknown; url: URL }> {
  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const response = await fetchFn(current, {
      redirect: "manual",
      headers: { accept: "application/json" },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (location === null) throw new PoppyProtocolError(`${what} redirect has no Location`);
      current = httpsUrl(new URL(location, current).href, `${what} redirect`);
      continue;
    }
    if (!response.ok) throw new PoppyProtocolError(`${what} returned HTTP ${response.status}`);
    try {
      return { body: await response.json(), url: current };
    } catch {
      throw new PoppyProtocolError(`${what} is not JSON`);
    }
  }
  throw new PoppyProtocolError(`${what} redirected more than ${MAX_REDIRECTS} times`);
}

/** Posts a form. Never follows redirects, so credentials in the body stay at the endpoint they were meant for. */
export function postForm(
  fetchFn: Fetch,
  url: string,
  body: URLSearchParams,
  headers: Record<string, string> = {},
) {
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
