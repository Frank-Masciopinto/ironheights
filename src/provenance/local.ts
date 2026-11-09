import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hostOf } from '../rules/network.ts';

/**
 * Local provenance for a skill folder. No registry and no signature.
 * A record is the name, the version string, and the content digest.
 * Comparing two records is how same-version drift is detected.
 */

export interface LocalIdentity {
  name: string;
  version: string | null;
  digest: string;
}

export type IdentityDrift =
  | { kind: 'unchanged' }
  | { kind: 'renamed'; previousName: string; name: string }
  | {
      kind: 'same-version-drift';
      name: string;
      version: string;
      previousDigest: string;
      digest: string;
    }
  | {
      kind: 'name-stable-bytes-changed';
      name: string;
      previousDigest: string;
      digest: string;
    };

export function identityDrift(previous: LocalIdentity, current: LocalIdentity): IdentityDrift {
  if (previous.name !== current.name) {
    return { kind: 'renamed', previousName: previous.name, name: current.name };
  }
  if (previous.digest === current.digest) return { kind: 'unchanged' };
  if (previous.version !== null && previous.version === current.version) {
    return {
      kind: 'same-version-drift',
      name: current.name,
      version: current.version,
      previousDigest: previous.digest,
      digest: current.digest,
    };
  }
  return {
    kind: 'name-stable-bytes-changed',
    name: current.name,
    previousDigest: previous.digest,
    digest: current.digest,
  };
}

export interface LockProblem {
  path: string;
  problem: 'missing' | 'changed' | 'not-a-file';
}

/** Compare files named in a lock to the bytes in `dir`. Paths are relative. */
export function lockProblems(dir: string, files: Record<string, string>): LockProblem[] {
  const problems: LockProblem[] = [];
  for (const [rel, want] of Object.entries(files)) {
    const abs = join(dir, rel);
    let info;
    try {
      info = lstatSync(abs);
    } catch {
      problems.push({ path: rel, problem: 'missing' });
      continue;
    }
    if (!info.isFile()) {
      problems.push({ path: rel, problem: 'not-a-file' });
      continue;
    }
    const got = createHash('sha256').update(readFileSync(abs)).digest('hex');
    if (got !== want) problems.push({ path: rel, problem: 'changed' });
  }
  return problems;
}

export interface EvidenceReceipt {
  tool: string;
  version: string;
  command: string;
  skillSha256: string | null;
  contentDigest: string | null;
  verdict: string;
  findings: Array<{ ruleId: string; severity: string; file: string; line?: number }>;
  findingsDigest: string;
}

export function findingsDigest(findings: EvidenceReceipt['findings']): string {
  const lines = findings
    .map((f) => `${f.ruleId}\0${f.severity}\0${f.file}\0${f.line ?? ''}`)
    .sort();
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}

export function buildEvidence(input: Omit<EvidenceReceipt, 'findingsDigest'>): EvidenceReceipt {
  return { ...input, findingsDigest: findingsDigest(input.findings) };
}

/** A receipt is reproducible only when the command, version, skill hash, and findings digest are present and agree. */
export function verifyEvidence(receipt: EvidenceReceipt): { ok: boolean; problems: string[] } {
  const problems: string[] = [];
  if (!receipt.command.trim()) problems.push('missing command');
  if (!receipt.version.trim()) problems.push('missing version');
  if (!receipt.skillSha256 || !/^[0-9a-f]{64}$/i.test(receipt.skillSha256))
    problems.push('missing skill sha256');
  if (!receipt.contentDigest || !/^[0-9a-f]{64}$/i.test(receipt.contentDigest))
    problems.push('missing content digest');
  const again = findingsDigest(receipt.findings);
  if (again !== receipt.findingsDigest)
    problems.push('findings digest does not match the finding list');
  return { ok: problems.length === 0, problems };
}

const PROXY_ASSIGN =
  /\b(?:HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)\s*=\s*['"]?(https?:\/\/[^\s'";]+)/gi;

/** Hosts a tool call sets as a proxy. Ambient operator environment is not this list. */
export function proxyHostsInText(text: string): string[] {
  const hosts: string[] = [];
  for (const match of text.matchAll(PROXY_ASSIGN)) {
    const host = hostOf(match[1] ?? '');
    if (host && !hosts.includes(host)) hosts.push(host);
  }
  return hosts;
}
