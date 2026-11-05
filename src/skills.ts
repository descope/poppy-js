import type { Company, Skill } from "./discovery.ts";
import { PoppyProtocolError } from "./errors.ts";
import { type Fetch, getBytes } from "./http.ts";

export interface FetchSkillOptions {
  /** Defaults to the global `fetch`. */
  fetch?: Fetch;
  allowPrivateAddresses?: boolean;
}

/** A skill artifact whose digest matched its `skill_index` entry (spec 9.4). */
export interface SkillArtifact {
  skill: Skill;
  /** The artifact's raw bytes. */
  bytes: Uint8Array;
  /**
   * The `SKILL.md` text, for a `skill-md` skill. An `archive` skill is left to you to unpack, following the
   * Agent Skills discovery proposal's layout and extraction checks.
   */
  text: string | undefined;
}

/**
 * Fetches one skill from a Company's `skill_index` and checks its `digest` (spec 9.4). The request carries
 * no Session header, token or other credential, wherever the artifact is. A skill is Company content: it
 * grants no account access and supplies no User approval, and you mustn't run its scripts unless the User
 * or your configuration allows it.
 */
export async function fetchSkill(
  company: Company,
  name: string,
  options: FetchSkillOptions = {},
): Promise<SkillArtifact> {
  const skill = company.skills.find((entry) => entry.name === name);
  if (skill === undefined) throw new PoppyProtocolError(`${company.domain} lists no skill ${name}`);
  const bytes = await getBytes(
    options.fetch ?? fetch,
    new URL(skill.url),
    "skill artifact",
    options.allowPrivateAddresses ?? false,
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
  const hex = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  if (`sha256:${hex}` !== skill.digest)
    throw new PoppyProtocolError(`skill ${name} doesn't match its digest`);
  return {
    skill,
    bytes,
    text:
      skill.type === "skill-md"
        ? new TextDecoder("utf-8", { fatal: true }).decode(bytes)
        : undefined,
  };
}
