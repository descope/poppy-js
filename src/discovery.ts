import { PoppyProtocolError } from "./errors.ts";
import { type Fetch, getJson, httpsUrl, isObject } from "./http.ts";

const SUPPORTED_MAJOR = "0";

/** One entry of `apis` in poppy.json (spec section 6). */
export interface Api {
  type: string;
  url: string;
  description?: string;
  resource?: string;
}

/** The parts of a Company's poppy.json and OAuth metadata this client uses, after validation. */
export interface Company {
  /** The host that served poppy.json, after redirects. Equals `organization.domain`, ignoring case. */
  domain: string;
  name: string;
  issuer: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
  deviceAuthorizationEndpoint: string | undefined;
  /** Scopes Device Sign-In can grant, or undefined when the Company does not offer it. */
  deviceScopes: readonly string[] | undefined;
  customScopes: Readonly<Record<string, string>>;
  apis: readonly Api[];
  /** Hosts an authenticated request may go to: the domain's own hosts plus every API and Company Agent host. */
  allowedHosts: readonly string[];
  /** The poppy.json document as published, for fields this client does not model. */
  document: Record<string, unknown>;
}

function string(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "") throw new PoppyProtocolError(`${what} is missing`);
  return value;
}

function stringList(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new PoppyProtocolError(`${what} must be a list of strings`);
  }
  return value;
}

/** RFC 8414 section 3: the well-known suffix goes between the host and the issuer's path. */
export function metadataUrl(issuer: string): URL {
  const url = httpsUrl(issuer, "auth.issuer");
  const path = url.pathname.replace(/\/$/, "");
  return new URL(`${url.origin}/.well-known/oauth-authorization-server${path}`);
}

function websiteUrl(website: string): URL {
  const url = httpsUrl(website.includes("://") ? website : `https://${website}`, "website");
  return new URL("/.well-known/poppy.json", url.origin);
}

const KNOWN_API_TYPES = new Set(["openapi", "mcp"]);

/** Keeps the API types this version knows and skips the rest unchecked, so later types can be added (spec 6). */
function parseApis(value: unknown): Api[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new PoppyProtocolError("apis must be a list");
  const apis: Api[] = [];
  value.forEach((entry, index) => {
    if (!isObject(entry)) throw new PoppyProtocolError(`apis[${index}] must be an object`);
    const type = entry["type"];
    if (typeof type !== "string" || !KNOWN_API_TYPES.has(type)) return;
    const api: Api = { type, url: httpsUrl(entry["url"], `apis[${index}].url`).href };
    if (typeof entry["description"] === "string") api.description = entry["description"];
    if (typeof entry["resource"] === "string") api.resource = entry["resource"];
    apis.push(api);
  });
  return apis;
}

/** Hosts of the `poppy` conversation endpoints; other protocol types are skipped unchecked (spec 7.1). */
function agentHosts(agent: unknown): string[] {
  if (!isObject(agent) || !Array.isArray(agent["protocols"])) return [];
  return agent["protocols"].flatMap((protocol, index) =>
    isObject(protocol) && protocol["type"] === "poppy"
      ? [httpsUrl(protocol["endpoint"], `agent.protocols[${index}].endpoint`).hostname]
      : [],
  );
}

/**
 * Fetches and checks a Company's poppy.json and its issuer's OAuth metadata (spec 3, 3.2).
 *
 * Throws {@link PoppyProtocolError} when anything fails a check the spec requires, so no token is ever sent to
 * a Company that did not prove it owns the issuer.
 */
export async function discover(website: string, options: { fetch?: Fetch } = {}): Promise<Company> {
  const fetchFn = options.fetch ?? fetch;
  const { body: doc, url: finalUrl } = await getJson(fetchFn, websiteUrl(website), "poppy.json");
  if (!isObject(doc)) throw new PoppyProtocolError("poppy.json must be an object");

  const version = string(doc["protocol_version"], "protocol_version");
  if (version.split(".")[0] !== SUPPORTED_MAJOR) {
    throw new PoppyProtocolError(`protocol_version ${version} is not supported`);
  }

  const organization = doc["organization"];
  if (!isObject(organization)) throw new PoppyProtocolError("organization is missing");
  const domain = string(organization["domain"], "organization.domain").toLowerCase();
  if (domain !== finalUrl.hostname) {
    throw new PoppyProtocolError(
      `organization.domain ${domain} does not match the host that served it`,
    );
  }

  const auth = doc["auth"];
  if (!isObject(auth))
    throw new PoppyProtocolError("auth is missing, so this Company offers no Sessions");
  const issuer = string(auth["issuer"], "auth.issuer");
  const device = auth["device"];
  const deviceScopes = isObject(device)
    ? stringList(device["scopes"], "auth.device.scopes")
    : undefined;

  const { body: metadata } = await getJson(fetchFn, metadataUrl(issuer), "OAuth metadata");
  if (!isObject(metadata)) throw new PoppyProtocolError("OAuth metadata must be an object");
  if (metadata["issuer"] !== issuer)
    throw new PoppyProtocolError("OAuth metadata issuer does not match auth.issuer");
  const poppyDomains = stringList(metadata["poppy_domains"] ?? null, "poppy_domains");
  if (!poppyDomains.some((entry) => entry.toLowerCase() === domain)) {
    throw new PoppyProtocolError(`poppy_domains does not list ${domain}`);
  }
  const algs = stringList(
    metadata["dpop_signing_alg_values_supported"] ?? null,
    "dpop_signing_alg_values_supported",
  );
  if (!algs.includes("ES256"))
    throw new PoppyProtocolError("dpop_signing_alg_values_supported must include ES256");

  const apis = parseApis(doc["apis"]);
  const customScopes = isObject(auth["custom_scopes"]) ? auth["custom_scopes"] : {};
  return {
    domain,
    name: typeof organization["name"] === "string" ? organization["name"] : domain,
    issuer,
    tokenEndpoint: httpsUrl(metadata["token_endpoint"], "token_endpoint").href,
    revocationEndpoint: httpsUrl(metadata["revocation_endpoint"], "revocation_endpoint").href,
    deviceAuthorizationEndpoint:
      deviceScopes === undefined
        ? undefined
        : httpsUrl(metadata["device_authorization_endpoint"], "device_authorization_endpoint").href,
    deviceScopes,
    customScopes: Object.fromEntries(
      Object.entries(customScopes).filter(([, v]) => typeof v === "string"),
    ) as Record<string, string>,
    apis,
    allowedHosts: [
      ...new Set([
        domain,
        ...apis.map((api) => new URL(api.url).hostname),
        ...agentHosts(doc["agent"]),
      ]),
    ],
    document: doc,
  };
}

/** Whether an authenticated request to `host` may carry this Company's Session Token. */
export function isAllowedHost(company: Company, host: string): boolean {
  const lower = host.toLowerCase();
  return lower.endsWith(`.${company.domain}`) || company.allowedHosts.includes(lower);
}
