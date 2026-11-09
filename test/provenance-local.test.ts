import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';
import {
  buildEvidence,
  identityDrift,
  verifyEvidence,
  type LocalIdentity,
} from '../src/provenance/local.ts';

const skill = `---
name: notes
version: 1.0.0
description: Takes meeting notes.
---
# Notes
Summarize the notes the user pastes.
`;

describe('local provenance', () => {
  it('reports same-version drift and leaves a renamed folder as renamed', () => {
    const previous: LocalIdentity = { name: 'notes', version: '1.0.0', digest: 'a'.repeat(64) };
    const drifted: LocalIdentity = { name: 'notes', version: '1.0.0', digest: 'b'.repeat(64) };
    expect(identityDrift(previous, drifted).kind).toBe('same-version-drift');
    const bumped: LocalIdentity = { name: 'notes', version: '1.0.1', digest: 'b'.repeat(64) };
    expect(identityDrift(previous, bumped).kind).toBe('name-stable-bytes-changed');
    expect(identityDrift(previous, previous).kind).toBe('unchanged');
  });

  it('rejects a receipt that drops a finding or omits the command', () => {
    const receipt = buildEvidence({
      tool: 'ironheights',
      version: '0.34.0',
      command: 'npx ironheights scan --json .',
      skillSha256: 'c'.repeat(64),
      contentDigest: 'd'.repeat(64),
      verdict: 'review',
      findings: [{ ruleId: 'IH-INJ-017', severity: 'medium', file: 'SKILL.md', line: 4 }],
    });
    expect(verifyEvidence(receipt).ok).toBe(true);
    const trimmed = { ...receipt, findings: [] };
    expect(verifyEvidence(trimmed).ok).toBe(false);
    expect(verifyEvidence({ ...receipt, command: ' ' }).problems).toContain('missing command');
  });

  it('reviews a folder whose shipped lock does not match, and ignores a folder with no lock', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-prov-'));
    await writeFile(join(dir, 'SKILL.md'), skill);
    const clean = await scanPath(dir, emptyConfig());
    expect(clean.skills[0]?.findings.some((f) => f.ruleId === 'IH-PROV-001')).toBe(false);

    const bytes = await readFile(join(dir, 'SKILL.md'));
    await writeFile(
      join(dir, 'ironheights.lock.json'),
      JSON.stringify({
        lockVersion: 1,
        skill: 'notes',
        digest: 'e'.repeat(64),
        files: { 'SKILL.md': 'f'.repeat(64) },
      }),
    );
    const bad = await scanPath(dir, emptyConfig());
    expect(bad.skills[0]?.findings.some((f) => f.ruleId === 'IH-PROV-001')).toBe(true);
    expect(bad.skills[0]?.verdict).toBe('review');
    expect(bytes.length).toBeGreaterThan(0);
  });
});
