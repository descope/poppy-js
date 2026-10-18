/**
 * Where a {@link PoppyAgent} keeps per-User state: the DPoP private key, the Session ID and the Account Token.
 *
 * Values are secrets (spec 4.8). Back this with encrypted storage in production.
 */
export interface Store {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  /** Not called by the SDK. Callers use it to forget a User; see the README for the key format. */
  delete(key: string): Promise<void>;
}

/** Keeps state in process memory. State is lost on exit, so every restart starts new Sessions. */
export class MemoryStore implements Store {
  readonly #values = new Map<string, string>();

  async get(key: string): Promise<string | undefined> {
    return this.#values.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    this.#values.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.#values.delete(key);
  }
}
