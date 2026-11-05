// Vendored stub: the types fake-company.ts needs from the validator's HTTP client.
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;
export type HttpOptions = Record<string, unknown>;
export type Http = unknown;
export function createHttp(_options: unknown): Http {
  throw new Error("not vendored");
}
