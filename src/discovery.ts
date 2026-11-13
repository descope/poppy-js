import { PoppyError, PoppyProtocolError } from "./errors.ts";
import {
  authorizationServerMetadataUrl,
  checkPublicHost,
  type Fetch,
  getJson,
  httpsUrl,
  isObject,
  originOf,
  resourceMetadataUrl,
} from "./http.ts";

/**
 * The `major.minor` versions this client implements, newest first (spec 3.1, 3.4). A Company serves one
 * version in `poppy.json` and may list others in `supported_versions`; {@link discover} picks the newest
 * of them this list names and uses that version's document.
 */
export const SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = ["0.4", "0.3"];

/**
 * The only scope the protocol defines (spec 4.7, section 6), from 0.4: it signs the agent's browser in to
 * the Company's website in a browser join. Request it only from a Company that lists
 * `browser_session_endpoint`, and read {@link Company.webUnscoped} first to see what it allows there.
 */
export const BROWSER_SIGN_IN_SCOPE = "poppy:browser-sign-in";

export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
export const MEDIATED_SIGN_IN_GRANT = "https://personalagentprotocol.org/grant/mediated-sign-in";

/** One entry of `apis` (spec section 7). Entries of unknown types are dropped. */
export interface Api {
  type: "openapi" | "mcp";
  url: string;
  description: string | undefined;
}

/** One `poppy` entry of `agent.protocols` (spec 3.2, 8.1). */
export interface ConversationProtocol {
  type: "poppy";
  endpoint: string;
  /** `signed_in` when the interface needs account access before useful work can begin (spec 3.2). */
  access: "session" | "signed_in";
}

/** What a scope allows, from `auth.scope_hints` (spec 4.7). */
export interface ScopeHint {
  /** Unknown values are read as `irreversible`. */
  changes: "none" | "reversible" | "irreversible";
  personalData: boolean;
}

/** A field of the Mediated Sign-In extension (extension section 2). */
export interface MediatedSignInField {
  name: string;
  label: string;
  secret: boolean;
}

export interface MediatedSignInConfig {
  fields: readonly MediatedSignInField[];
  scopes: readonly string[];
}

/** The OAuth server metadata this client uses (spec 3.2). */
export interface OAuthServer {
  issuer: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
  authorizationEndpoint: string | undefined;
  deviceAuthorizationEndpoint: string | undefined;
  grantTypesSupported: readonly string[];
  scopesSupported: readonly string[] | undefined;
  /** `protected_resources`, as published. */
  protectedResources: readonly string[];
  /** `dpop_signing_alg_values_supported`; the client sends DPoP proofs when it lists ES256 (spec 4.5). */
  dpopSigningAlgValuesSupported: readonly string[] | undefined;
  /** `token_endpoint_auth_signing_alg_values_supported` (spec 4.1). */
  tokenEndpointAuthSigningAlgValuesSupported: readonly string[] | undefined;
}

/**
 * One skill from a `skill_index` (spec 9.4). Content from the Company: it grants nothing.
 *
 * On 0.3 the index is in `poppy.json` and {@link Company.skills} holds it. On 0.4 it is in the response
 * from `tasks.endpoint`, so it belongs to one Session; read it with `Session.taskCoverage()`.
 */
export interface Skill {
  name: string;
  description: string;
  /** `skill-md` for a single `SKILL.md`, or `archive` for a skill with supporting files. */
  type: "skill-md" | "archive";
  /** Resolved against the final `poppy.json` URL. May be on another domain, which gets no credentials. */
  url: string;
  /** `sha256:` and the artifact's SHA-256 in lowercase hex. {@link fetchSkill} checks it. */
  digest: string;
}

/** The Agent Skills discovery schema `skill_index` uses (spec 9.4). Other values are ignored. */
export const SKILL_INDEX_SCHEMA = "https://schemas.agentskills.io/discovery/0.2.0/schema.json";

/** How the Company connects through the UCP extension, version 1. */
export interface UcpExtensionInfo {
  /** `https://{domain}/.well-known/ucp`, fetched without following redirects (UCP extension 3). */
  profileUrl: string;
  /** Whether `agent.protocols` lists UCP Ask as a conversation protocol (UCP extension 5). */
  ask: boolean;
}

/** An extension entry from `poppy.json` (spec 3.3), with its own fields kept as published. */
export interface ExtensionEntry {
  version: string;
  [field: string]: unknown;
}

/** A Company's `poppy.json` and OAuth metadata, after every check in spec section 3. */
export interface Company {
  /**
   * The version negotiated with this Company (spec 3.4): the newest of the versions it serves that
   * {@link SUPPORTED_PROTOCOL_VERSIONS} names. Everything else here, and the requests this SDK sends,
   * follow it, so keep the Company you discovered rather than mixing documents.
   */
  protocolVersion: string;
  /** The URL the chosen version's document was read from, which skill and index URLs resolve against. */
  documentUrl: string;
  /** The other versions the Company serves, each mapped to its document's URL (spec 3.4). */
  supportedVersions: Readonly<Record<string, string>>;
  /** The host that served `poppy.json`, after redirects; equals `organization.domain`, lowercased. */
  domain: string;
  name: string;
  /** `organization.logo_uri`. Show it with the Company's name and domain (spec 3.1). */
  logoUri: string | undefined;
  /**
   * The Company's identifier (spec 3.2): its issuer when it has one, else `https://{domain}`. Session JWTs
   * name it in `aud`, and User IDs are scoped by it.
   */
  identifier: string;
  /** Undefined when the Company has no issuer, and so offers only signed-out Sessions. */
  oauth: OAuthServer | undefined;
  /**
   * Sign-in types the Company offers (spec 4, Mediated Sign-In extension). All are off when it sets
   * `auth.disabled` (spec 3.2). The Company can still refuse one to your agent with `unauthorized_client`.
   */
  signIn: {
    /** `auth.disabled`: the Company offers Personal Agents no sign-in, though it has an issuer. */
    disabled: boolean;
    direct: boolean;
    device: boolean;
    mediated: MediatedSignInConfig | undefined;
  };
  /** Scope descriptions from `auth.scopes` (spec 4.7). */
  scopes: Readonly<Record<string, string>>;
  scopeHints: Readonly<Record<string, ScopeHint>>;
  /**
   * Scopes from `scopes_supported` in the domain's protected resource metadata (RFC 9728 section 2,
   * spec 3.2, 4.7). A Personal Agent can request the scopes in this list or the issuer's.
   */
  resourceScopesSupported: readonly string[] | undefined;
  conversationProtocols: readonly ConversationProtocol[];
  apis: readonly Api[];
  browserSessionEndpoint: string | undefined;
  /**
   * `web.disabled` (spec 3.1, section 6), from 0.4: the Company asks Personal Agents not to browse its
   * website in a browser, and to use its Company Agent and APIs instead. Pages fetched without a browser
   * aren't covered. Always false on 0.3.
   */
  webDisabled: boolean;
  /**
   * `web.unscoped` (spec 3.1, section 6), from 0.4: the website doesn't apply the Company's other scopes,
   * so {@link BROWSER_SIGN_IN_SCOPE} gives the account's full access there. Always false on 0.3.
   */
  webUnscoped: boolean;
  /**
   * `feedback.endpoint` (spec 9.3). Set only on 0.3, where it is in `poppy.json`; on 0.4 it comes from
   * `tasks.endpoint` for each Session, so read it with `Session.taskCoverage()`.
   */
  feedbackEndpoint: string | undefined;
  /** `excluded_tasks.url` (spec 9.1). Set only on 0.3; on 0.4 excluded tasks come from `tasksEndpoint`. */
  excludedTasksUrl: string | undefined;
  /**
   * `tasks.endpoint` (spec section 9), from 0.4: where a Session gets the Company's excluded tasks,
   * skills and feedback endpoint. Undefined on 0.3.
   */
  tasksEndpoint: string | undefined;
  /**
   * The extensions the Company lists, keyed by name (spec 3.3). Each name has one entry per major
   * version it supports, newest first as published. A 0.3 document lists one entry per extension, which
   * is read as a list of one, so the same code reads both versions.
   */
  extensions: Readonly<Record<string, readonly ExtensionEntry[]>>;
  /**
   * Skills from `skill_index` in `poppy.json` (spec 9.4). Set only on 0.3; on 0.4 the index comes from
   * `tasks.endpoint` for each Session, so read it with `Session.taskCoverage()`.
   */
  skills: readonly Skill[];
  /** Set when the Company lists the UCP extension, version 1. */
  ucp: UcpExtensionInfo | undefined;
}

export interface DiscoverOptions {
  /** Defaults to the global `fetch`. Every request is sent with `redirect: "manual"`. */
  fetch?: Fetch;
  /** Allow loopback, private and link-local hosts, such as `localhost` in tests. Off by default (spec 3). */
  allowPrivateAddresses?: boolean;
}

function string(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "") throw new PoppyProtocolError(`${what} is missing`);
  return value;
}

function optionalStringList(value: unknown, what: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new PoppyProtocolError(`${what} must be a list of strings`);
  }
  return value;
}

const VERSION = /^(\d+)\.(\d+)$/;

/**
 * Orders `major.minor` versions. Returns undefined for anything that isn't one, which is never chosen.
 */
function versionOrder(version: string): number | undefined {
  const match = VERSION.exec(version);
  if (match === null) return undefined;
  return Number(match[1]) * 100_000 + Number(match[2]);
}

/**
 * Reads `supported_versions` (spec 3.4): the other versions the Company serves, each mapped to the URL of
 * that version's document. Each URL MUST be HTTPS on the host that served `poppy.json` after redirects,
 * so one domain's document can't make a file uploaded to another speak for that Company. An entry that
 * isn't a `major.minor` version, or whose URL fails a check, is dropped rather than failing discovery,
 * since the Company's own version still works.
 *
 * `supported_versions` maps the OTHER versions a Company serves, so an entry for the version this very
 * document declares is dropped too: the document is already here and already checked, and following a
 * link for it would fetch a second copy and could fail over one that is broken.
 */
function parseSupportedVersions(
  value: unknown,
  finalUrl: URL,
  publishedVersion: string,
): Record<string, string> {
  if (!isObject(value)) return {};
  // `host`, not `hostname`: a document on another port is not on the host that served poppy.json.
  const host = finalUrl.host.toLowerCase();
  const versions: Record<string, string> = {};
  for (const [version, url] of Object.entries(value)) {
    if (version === publishedVersion) continue;
    if (versionOrder(version) === undefined || typeof url !== "string") continue;
    let parsed: URL;
    try {
      parsed = new URL(url, finalUrl);
    } catch {
      continue;
    }
    if (parsed.protocol !== "https:") continue;
    if (parsed.host.toLowerCase() !== host) continue;
    versions[version] = parsed.href;
  }
  return versions;
}

/**
 * Picks the newest version the Company serves that this client implements (spec 3.4). Two versions are
 * compatible when they have the same major version and, before 1.0, the same minor version, so a version
 * this client implements is simply one of {@link SUPPORTED_PROTOCOL_VERSIONS}.
 */
function choosableVersions(
  documentVersion: string,
  supportedVersions: Readonly<Record<string, string>>,
): string[] {
  return [documentVersion, ...Object.keys(supportedVersions)]
    .filter((version) => SUPPORTED_PROTOCOL_VERSIONS.includes(version))
    .map((version) => ({ version, order: versionOrder(version) }))
    .filter((entry): entry is { version: string; order: number } => entry.order !== undefined)
    .sort((a, b) => b.order - a.order)
    .map((entry) => entry.version);
}

/**
 * Fetches the document a `supported_versions` entry links to (spec 3.4). It is never followed through a
 * redirect, carries the `protocol_version` it was listed under, and has no `supported_versions` of its
 * own, so a chain of links can't take the agent somewhere else.
 */
async function fetchLinkedDocument(
  fetchFn: Fetch,
  url: string,
  version: string,
  allowPrivate: boolean,
): Promise<Record<string, unknown>> {
  const { body } = await getJson(fetchFn, new URL(url), `the ${version} document`, {
    allowPrivate,
    followRedirects: false,
  });
  if (!isObject(body)) throw new PoppyProtocolError(`the ${version} document must be an object`);
  if (body["protocol_version"] !== version)
    throw new PoppyProtocolError(
      `the document listed under ${version} declares protocol_version ${String(body["protocol_version"])}`,
    );
  if (body["supported_versions"] !== undefined)
    throw new PoppyProtocolError(`the ${version} document must not have supported_versions`);
  return body;
}

function websiteUrl(website: string): URL {
  const url = httpsUrl(website.includes("://") ? website : `https://${website}`, "website");
  return new URL("/.well-known/poppy.json", url.origin);
}

/** Unknown API types are skipped unchecked so later types can be added (spec 7). */
function parseApis(value: unknown): Api[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new PoppyProtocolError("apis must be a list");
  const apis: Api[] = [];
  value.forEach((entry, index) => {
    if (!isObject(entry)) throw new PoppyProtocolError(`apis[${index}] must be an object`);
    const type = entry["type"];
    if (type !== "openapi" && type !== "mcp") return;
    apis.push({
      type,
      url: httpsUrl(entry["url"], `apis[${index}].url`).href,
      description: typeof entry["description"] === "string" ? entry["description"] : undefined,
    });
  });
  return apis;
}

/** Unknown protocol types are skipped, and unknown `access` values read as absent (spec 3.2, 8.1). */
function parseProtocols(agent: unknown): ConversationProtocol[] {
  if (agent === undefined) return [];
  if (!isObject(agent) || !Array.isArray(agent["protocols"]))
    throw new PoppyProtocolError("agent.protocols must be a list");
  return agent["protocols"].flatMap((protocol, index): ConversationProtocol[] => {
    if (!isObject(protocol) || protocol["type"] !== "poppy") return [];
    return [
      {
        type: "poppy",
        endpoint: httpsUrl(protocol["endpoint"], `agent.protocols[${index}].endpoint`).href,
        access: protocol["access"] === "signed_in" ? "signed_in" : "session",
      },
    ];
  });
}

function parseScopes(value: unknown): Record<string, string> {
  if (!isObject(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

function parseScopeHints(value: unknown): Record<string, ScopeHint> {
  if (!isObject(value)) return {};
  const hints: Record<string, ScopeHint> = {};
  for (const [scope, hint] of Object.entries(value)) {
    if (!isObject(hint)) continue;
    const changes = hint["changes"];
    hints[scope] = {
      changes: changes === "none" || changes === "reversible" ? changes : "irreversible",
      // A missing or unknown value is read as the more consequential answer.
      personalData: hint["personal_data"] !== false,
    };
  }
  return hints;
}

/**
 * Reads `extensions` (spec 3.3). On 0.4 each name maps to a list with an entry for each major version
 * the Company supports; on 0.3 it maps to one entry, which is read as a list of one. Entries of an
 * unknown shape are skipped, since either side works without an extension it doesn't support.
 */
function parseExtensions(value: unknown, version: string): Record<string, ExtensionEntry[]> {
  if (!isObject(value)) return {};
  const extensions: Record<string, ExtensionEntry[]> = {};
  for (const [name, listed] of Object.entries(value)) {
    const entries = (version === "0.3" ? [listed] : Array.isArray(listed) ? listed : []).flatMap(
      (entry): ExtensionEntry[] =>
        isObject(entry) && typeof entry["version"] === "string" ? [entry as ExtensionEntry] : [],
    );
    if (entries.length > 0) extensions[name] = entries;
  }
  return extensions;
}

/** The Company's entry for `name` at `version`, or undefined when it doesn't list that version. */
function extensionEntry(
  extensions: Readonly<Record<string, readonly ExtensionEntry[]>>,
  name: string,
  version: string,
): ExtensionEntry | undefined {
  return extensions[name]?.find((entry) => entry.version === version);
}

const RESERVED_MEDIATED_FIELDS = new Set([
  "grant_type",
  "scope",
  "resource",
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "sign_in_id",
  "one_time_code",
]);

function parseMediated(entry: ExtensionEntry | undefined): MediatedSignInConfig | undefined {
  if (entry === undefined) return undefined;
  const fields = entry["fields"];
  const scopes = entry["scopes"];
  if (!Array.isArray(fields) || !Array.isArray(scopes)) return undefined;
  const parsed: MediatedSignInField[] = [];
  for (const field of fields) {
    if (!isObject(field) || typeof field["name"] !== "string" || field["name"] === "")
      throw new PoppyProtocolError("mediated-sign-in fields need a name");
    if (RESERVED_MEDIATED_FIELDS.has(field["name"]))
      throw new PoppyProtocolError(`mediated-sign-in field ${field["name"]} is a reserved name`);
    parsed.push({
      name: field["name"],
      label: typeof field["label"] === "string" ? field["label"] : field["name"],
      // Treat a field as secret unless the Company says it isn't.
      secret: field["secret"] !== false,
    });
  }
  return {
    fields: parsed,
    scopes: scopes.filter((scope): scope is string => typeof scope === "string"),
  };
}

const DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * Reads a `skill_index` (spec 9.4). The index is ignored when `$schema` is absent or unknown, and entries
 * of an unknown `type`, or that are malformed, are skipped, so the rest of the document stays usable.
 * `base` is the final `poppy.json` URL on 0.3 and `tasks.endpoint` on 0.4, as each version resolves
 * relative references against the document the index came in.
 */
export function parseSkillIndex(value: unknown, base: URL): Skill[] {
  if (
    !isObject(value) ||
    value["$schema"] !== SKILL_INDEX_SCHEMA ||
    !Array.isArray(value["skills"])
  )
    return [];
  return value["skills"].flatMap((entry): Skill[] => {
    if (!isObject(entry)) return [];
    const { name, description, type, url, digest } = entry;
    if (typeof name !== "string" || typeof description !== "string" || typeof url !== "string")
      return [];
    if ((type !== "skill-md" && type !== "archive") || typeof digest !== "string") return [];
    if (!DIGEST.test(digest)) return [];
    let resolved: URL;
    try {
      // RFC 3986 section 5, against the final poppy.json URL.
      resolved = new URL(url, base);
    } catch {
      return [];
    }
    if (resolved.protocol !== "https:") return [];
    return [{ name, description, type, url: resolved.href, digest }];
  });
}

function parseUcp(
  extensions: Record<string, ExtensionEntry[]>,
  agent: unknown,
  domain: string,
): UcpExtensionInfo | undefined {
  if (extensionEntry(extensions, "ucp", "1") === undefined) return undefined;
  const profileUrl = `${originOf(domain)}/.well-known/ucp`;
  const protocols = isObject(agent) && Array.isArray(agent["protocols"]) ? agent["protocols"] : [];
  const ask = protocols.some(
    (protocol) =>
      isObject(protocol) && protocol["type"] === "ucp" && protocol["endpoint"] === profileUrl,
  );
  return { profileUrl, ask };
}

function optionalUrl(container: unknown, key: string, what: string): string | undefined {
  if (!isObject(container) || container[key] === undefined) return undefined;
  return httpsUrl(container[key], what).href;
}

/**
 * Finds the issuer from the domain's protected resource metadata (spec 3.2). Returns undefined when the
 * Company has no issuer, which only a 404 or an empty `authorization_servers` establishes.
 */
async function findIssuer(
  fetchFn: Fetch,
  domain: string,
  authIssuer: string | undefined,
  allowPrivate: boolean,
): Promise<{ issuer: string | undefined; scopesSupported: string[] | undefined }> {
  const resource = originOf(domain);
  const { status, body } = await getJson(
    fetchFn,
    resourceMetadataUrl(resource),
    "protected resource metadata",
    { allowPrivate, allowNotFound: true },
  );
  let servers: string[] = [];
  // The domain's own scopes (RFC 9728 section 2, spec 3.2): a Personal Agent can request the scopes
  // here or in the issuer's metadata, which a hosted issuer often can't tailor to one Company.
  let scopesSupported: string[] | undefined;
  if (status !== 404) {
    if (!isObject(body))
      throw new PoppyProtocolError("protected resource metadata must be an object");
    if (body["resource"] !== resource)
      throw new PoppyProtocolError(`protected resource metadata resource must be ${resource}`);
    servers = optionalStringList(body["authorization_servers"], "authorization_servers") ?? [];
    // 0.4 reads the domain's own scopes from here (spec 3.2, 4.7). 0.3 defines nothing here, and a
    // Company may have put anything in it, so a malformed value is ignored rather than refused.
    scopesSupported = Array.isArray(body["scopes_supported"])
      ? body["scopes_supported"].filter((scope): scope is string => typeof scope === "string")
      : undefined;
  }
  if (servers.length === 0) {
    if (authIssuer !== undefined)
      throw new PoppyProtocolError("auth.issuer is set, but the domain names no issuer");
    return { issuer: undefined, scopesSupported };
  }
  if (servers.length === 1) {
    if (authIssuer !== undefined && authIssuer !== servers[0])
      throw new PoppyProtocolError("auth.issuer must name the domain's authorization server");
    return { issuer: servers[0], scopesSupported };
  }
  if (authIssuer === undefined)
    throw new PoppyProtocolError("the domain lists several issuers, so auth.issuer is required");
  if (!servers.includes(authIssuer))
    throw new PoppyProtocolError("auth.issuer is not one of the domain's authorization servers");
  return { issuer: authIssuer, scopesSupported };
}

/** RFC 9728 section 3.3 comparison, with the host compared ignoring case (spec 3.2). */
function listsDomain(protectedResources: readonly string[], domain: string): boolean {
  return protectedResources.some((entry) => {
    const match = /^https:\/\/([^/?#:@]+)$/i.exec(entry);
    return match?.[1]?.toLowerCase() === domain;
  });
}

async function fetchOAuthServer(
  fetchFn: Fetch,
  issuer: string,
  domain: string,
  allowPrivate: boolean,
): Promise<OAuthServer> {
  httpsUrl(issuer, "issuer");
  const { body } = await getJson(
    fetchFn,
    authorizationServerMetadataUrl(issuer),
    "OAuth metadata",
    { allowPrivate },
  );
  if (!isObject(body)) throw new PoppyProtocolError("OAuth metadata must be an object");
  if (body["issuer"] !== issuer)
    throw new PoppyProtocolError("OAuth metadata issuer does not match the Company's issuer");
  const protectedResources =
    optionalStringList(body["protected_resources"], "protected_resources") ?? [];
  if (!listsDomain(protectedResources, domain))
    throw new PoppyProtocolError(`protected_resources does not list https://${domain}`);
  const grantTypes = optionalStringList(body["grant_types_supported"], "grant_types_supported");
  if (grantTypes === undefined || !grantTypes.includes("refresh_token"))
    throw new PoppyProtocolError("grant_types_supported must include refresh_token");
  const endpoint = (key: string, required: boolean) =>
    required || body[key] !== undefined ? httpsUrl(body[key], key).href : undefined;
  return {
    issuer,
    tokenEndpoint: string(endpoint("token_endpoint", true), "token_endpoint"),
    revocationEndpoint: string(endpoint("revocation_endpoint", true), "revocation_endpoint"),
    authorizationEndpoint: endpoint(
      "authorization_endpoint",
      grantTypes.includes("authorization_code"),
    ),
    deviceAuthorizationEndpoint: endpoint(
      "device_authorization_endpoint",
      grantTypes.includes(DEVICE_CODE_GRANT),
    ),
    grantTypesSupported: grantTypes,
    scopesSupported: optionalStringList(body["scopes_supported"], "scopes_supported"),
    protectedResources,
    dpopSigningAlgValuesSupported: optionalStringList(
      body["dpop_signing_alg_values_supported"],
      "dpop_signing_alg_values_supported",
    ),
    tokenEndpointAuthSigningAlgValuesSupported: optionalStringList(
      body["token_endpoint_auth_signing_alg_values_supported"],
      "token_endpoint_auth_signing_alg_values_supported",
    ),
  };
}

/** Everything one version's document says on its own, before the issuer's metadata is fetched. */
interface ParsedDocument {
  version: string;
  documentUrl: URL;
  domain: string;
  name: string;
  logoUri: string | undefined;
  disabled: boolean;
  authIssuer: string | undefined;
  scopes: Record<string, string>;
  scopeHints: Record<string, ScopeHint>;
  conversationProtocols: ConversationProtocol[];
  apis: Api[];
  extensions: Record<string, ExtensionEntry[]>;
  browserSessionEndpoint: string | undefined;
  webDisabled: boolean;
  webUnscoped: boolean;
  tasksEndpoint: string | undefined;
  feedbackEndpoint: string | undefined;
  excludedTasksUrl: string | undefined;
  skills: Skill[];
  ucp: UcpExtensionInfo | undefined;
}

/**
 * Reads and checks one version's document, with no requests of its own: everything here is what the
 * document says about itself. A document that fails any of it is one this client can't use, so
 * {@link discover} drops that version and tries the next one the Company serves (spec 3.4).
 *
 * `finalUrl` is where `poppy.json` was served, which every version's `organization.domain` names,
 * while `documentUrl` is where this version's document was read and what its relative URLs resolve
 * against (spec 3.1, 3.4, 9.4).
 */
function parseDocument(
  doc: Record<string, unknown>,
  version: string,
  documentUrl: URL,
  finalUrl: URL,
  allowPrivate: boolean,
): ParsedDocument {
  const organization = doc["organization"];
  if (!isObject(organization)) throw new PoppyProtocolError("organization is missing");
  const domain = string(organization["domain"], "organization.domain").toLowerCase();
  if (domain !== finalUrl.hostname.toLowerCase()) {
    throw new PoppyProtocolError(
      `organization.domain ${domain} does not match the host that served it`,
    );
  }
  if (doc["agent"] === undefined && doc["apis"] === undefined && doc["web"] === undefined)
    throw new PoppyProtocolError("poppy.json must list at least one of agent, apis, or web");

  const logoUri =
    organization["logo_uri"] === undefined
      ? undefined
      : httpsUrl(organization["logo_uri"], "organization.logo_uri").href;
  const auth = isObject(doc["auth"]) ? doc["auth"] : {};
  const conversationProtocols = parseProtocols(doc["agent"]);
  const apis = parseApis(doc["apis"]);
  const extensions = parseExtensions(doc["extensions"], version);
  const web = isObject(doc["web"]) ? doc["web"] : undefined;
  const browserSessionEndpoint = optionalUrl(
    web,
    "browser_session_endpoint",
    "web.browser_session_endpoint",
  );
  // 0.4 moved excluded tasks, skills and feedback behind one per-Session endpoint (spec section 9).
  const tasksEndpoint =
    version === "0.3" ? undefined : optionalUrl(doc["tasks"], "endpoint", "tasks.endpoint");
  const feedbackEndpoint =
    version === "0.3" ? optionalUrl(doc["feedback"], "endpoint", "feedback.endpoint") : undefined;
  const excludedTasksUrl =
    version === "0.3" ? optionalUrl(doc["excluded_tasks"], "url", "excluded_tasks.url") : undefined;
  const extensionEndpoints = Object.entries(extensions).flatMap(([name, entries]) =>
    entries.flatMap((entry) =>
      typeof entry["endpoint"] === "string"
        ? [httpsUrl(entry["endpoint"], `extensions.${name}.endpoint`).href]
        : [],
    ),
  );

  for (const url of [
    ...apis.map((api) => api.url),
    ...conversationProtocols.map((protocol) => protocol.endpoint),
    ...extensionEndpoints,
    browserSessionEndpoint,
    feedbackEndpoint,
    tasksEndpoint,
    excludedTasksUrl,
    logoUri,
  ]) {
    if (url !== undefined) checkPublicHost(new URL(url), "Company URL", allowPrivate);
  }

  return {
    version,
    documentUrl,
    domain,
    name: typeof organization["name"] === "string" ? organization["name"] : domain,
    logoUri,
    disabled: auth["disabled"] === true,
    authIssuer: auth["issuer"] === undefined ? undefined : string(auth["issuer"], "auth.issuer"),
    scopes: parseScopes(auth["scopes"]),
    scopeHints: parseScopeHints(auth["scope_hints"]),
    conversationProtocols,
    apis,
    extensions,
    browserSessionEndpoint,
    webDisabled: web?.["disabled"] === true && version !== "0.3",
    webUnscoped: web?.["unscoped"] === true && version !== "0.3",
    tasksEndpoint,
    feedbackEndpoint,
    excludedTasksUrl,
    skills: version === "0.3" ? parseSkillIndex(doc["skill_index"], documentUrl) : [],
    ucp: parseUcp(extensions, doc["agent"], domain),
  };
}

/**
 * Fetches a Company's `poppy.json`, its domain's protected resource metadata and its issuer's OAuth
 * metadata, and checks them as spec section 3 requires. Throws {@link PoppyProtocolError} on any failed
 * check, so nothing is sent to a Company that did not prove the link between its domain and issuer.
 *
 * When the Company serves several versions (spec 3.4), this picks the newest one this client implements
 * and reads that version's document. {@link Company.protocolVersion} says which it chose, and the
 * Session header carries it in `Poppy-Version` on every request.
 */
export async function discover(website: string, options: DiscoverOptions = {}): Promise<Company> {
  const fetchFn = options.fetch ?? fetch;
  const allowPrivate = options.allowPrivateAddresses ?? false;
  const { body: published, url: finalUrl } = await getJson(
    fetchFn,
    websiteUrl(website),
    "poppy.json",
    { allowPrivate },
  );
  // A redirect may only end at the well-known path, so an uploaded file can't speak for a domain (spec 3).
  if (finalUrl.pathname !== "/.well-known/poppy.json" || finalUrl.search !== "")
    throw new PoppyProtocolError("poppy.json redirected away from /.well-known/poppy.json");
  if (!isObject(published)) throw new PoppyProtocolError("poppy.json must be an object");

  const publishedVersion = string(published["protocol_version"], "protocol_version");
  const supportedVersions = parseSupportedVersions(
    published["supported_versions"],
    finalUrl,
    publishedVersion,
  );
  const choosable = choosableVersions(publishedVersion, supportedVersions);
  if (choosable.length === 0) {
    throw new PoppyProtocolError(
      `${[publishedVersion, ...Object.keys(supportedVersions)].join(", ")} is not a protocol version this client supports`,
    );
  }
  // Newest first, taking the document for each in turn. A document this client can't use is one it
  // MUST NOT use (spec 3.4), so its version drops out and the next newest is tried, rather than one
  // bad link costing the whole Company. Only what a document says about itself is checked here; the
  // issuer's metadata is fetched once, for the document that wins.
  let chosen: ParsedDocument | undefined;
  let refused: PoppyError | undefined;
  for (const candidate of choosable) {
    const linkedUrl = supportedVersions[candidate];
    try {
      const doc =
        linkedUrl === undefined
          ? published
          : await fetchLinkedDocument(fetchFn, linkedUrl, candidate, allowPrivate);
      chosen = parseDocument(
        doc,
        candidate,
        linkedUrl === undefined ? finalUrl : new URL(linkedUrl),
        finalUrl,
        allowPrivate,
      );
      break;
    } catch (error) {
      refused ??= error instanceof PoppyError ? error : undefined;
    }
  }
  if (chosen === undefined)
    throw refused ?? new PoppyProtocolError("no protocol version this client supports is usable");

  const { issuer, scopesSupported: resourceScopesSupported } = await findIssuer(
    fetchFn,
    chosen.domain,
    chosen.authIssuer,
    allowPrivate,
  );
  const oauth =
    issuer === undefined
      ? undefined
      : await fetchOAuthServer(fetchFn, issuer, chosen.domain, allowPrivate);
  if (oauth === undefined && chosen.conversationProtocols.some((p) => p.access === "signed_in"))
    throw new PoppyProtocolError("a signed_in conversation protocol needs an issuer");
  const disabled = chosen.disabled;
  const mediated =
    !disabled &&
    oauth?.grantTypesSupported.some((grant) => grant === MEDIATED_SIGN_IN_GRANT) === true
      ? parseMediated(extensionEntry(chosen.extensions, "mediated-sign-in", "1"))
      : undefined;
  for (const url of [
    oauth?.tokenEndpoint,
    oauth?.revocationEndpoint,
    oauth?.authorizationEndpoint,
    oauth?.deviceAuthorizationEndpoint,
  ]) {
    if (url !== undefined) checkPublicHost(new URL(url), "Company URL", allowPrivate);
  }

  return {
    protocolVersion: chosen.version,
    documentUrl: chosen.documentUrl.href,
    supportedVersions,
    domain: chosen.domain,
    name: chosen.name,
    logoUri: chosen.logoUri,
    identifier: issuer ?? originOf(chosen.domain),
    oauth,
    signIn: {
      disabled,
      direct: !disabled && oauth?.authorizationEndpoint !== undefined,
      device: !disabled && oauth?.deviceAuthorizationEndpoint !== undefined,
      mediated,
    },
    scopes: chosen.scopes,
    scopeHints: chosen.scopeHints,
    resourceScopesSupported,
    conversationProtocols: chosen.conversationProtocols,
    apis: chosen.apis,
    browserSessionEndpoint: chosen.browserSessionEndpoint,
    webDisabled: chosen.webDisabled,
    webUnscoped: chosen.webUnscoped,
    feedbackEndpoint: chosen.feedbackEndpoint,
    excludedTasksUrl: chosen.excludedTasksUrl,
    tasksEndpoint: chosen.tasksEndpoint,
    extensions: chosen.extensions,
    skills: chosen.skills,
    ucp: chosen.ucp,
  };
}

/** Whether the Company lists `name` at `version` in its `extensions` (spec 3.3). */
export function companySupports(company: Company, name: string, version: string): boolean {
  return extensionEntry(company.extensions, name, version) !== undefined;
}

/**
 * The Company's entry for an extension at a version, or undefined when it doesn't list that version
 * (spec 3.3). On 0.4 a Company lists one entry per major version, each with its own fields.
 */
export function companyExtension(
  company: Company,
  name: string,
  version: string,
): ExtensionEntry | undefined {
  return extensionEntry(company.extensions, name, version);
}

/**
 * The scopes a Personal Agent can request: those the issuer lists and those the domain's protected
 * resource metadata lists (spec 3.2, 4.7). From 0.4 either list may name them, and the agent uses both.
 */
export function supportedScopes(company: Company): string[] {
  return [
    ...new Set([
      ...(company.oauth?.scopesSupported ?? []),
      ...(company.resourceScopesSupported ?? []),
    ]),
  ];
}
