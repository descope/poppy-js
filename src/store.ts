/**
 * Holds per-User state: the DPoP private key, Session ID and Account Token.
 * Values are secrets (spec 4.8), so use encrypted storage in production.
 */
export interface Store {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  /** Called by {@link PoppyAgent.forget}. */
  delete(key: string): Promise<void>;
}

/** State is lost on exit, so every restart starts new Sessions. */
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
