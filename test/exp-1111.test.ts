import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';

const FIXTURES = join(process.cwd(), 'test/fixtures/exp-1111');

const KEPT: Record<string, string> = {
  ASB04_006382: 'IH-FS-003',
  ASB04_004004: 'IH-FS-003',
  ASB04_000101: 'IH-INJ-028',
  ASB04_001380: 'IH-EXEC-012',
  ASB04_005906: 'IH-NET-009',
  ASB04_003158: 'IH-EXEC-013',
  ASB04_003306: 'IH-INJ-029',
  ASB04_002784: 'IH-NET-010',
  ASB04_004302: 'IH-EXEC-014',
  ASB04_000683: 'IH-EXEC-015',
};

async function scan(dir: string) {
  const result = await scanPath(dir, emptyConfig());
  const skill = result.skills[0];
  return {
    verdict: skill?.verdict ?? 'missing',
    findings: skill?.findings ?? [],
    ids: skill?.findings.map((finding) => finding.ruleId) ?? [],
  };
}

describe('2026-11-11 combined checks', () => {
  it('blocks each kept missed-attack fixture', async () => {
    for (const [id, ruleId] of Object.entries(KEPT)) {
      const scanned = await scan(join(FIXTURES, 'attacks', id));
      expect(scanned.ids, id).toContain(ruleId);
      expect(scanned.verdict, id).toBe('block');
    }
  });

  it('blocks every wrapper rephrasing', async () => {
    const root = join(FIXTURES, 'attacks', 'ASB04_004302-variants');
    const dirs = await readdir(root);
    expect(dirs.length).toBeGreaterThan(0);
    for (const dir of dirs) {
      const scanned = await scan(join(root, dir));
      expect(scanned.ids, dir).toContain('IH-EXEC-014');
    }
  });

  it('does not fire on the skipped shapes', async () => {
    const addedIds = [
      'IH-FS-003',
      'IH-INJ-028',
      'IH-INJ-029',
      'IH-EXEC-012',
      'IH-EXEC-013',
      'IH-EXEC-014',
      'IH-EXEC-015',
      'IH-NET-009',
      'IH-NET-010',
    ];
    for (const id of ['ASB04_006270-skip', 'ASB04_005884-skip', 'ASB04_000452-skip']) {
      const scanned = await scan(join(FIXTURES, 'attacks', id));
      expect(
        scanned.ids.filter((ruleId) => addedIds.includes(ruleId)),
        id,
      ).toEqual([]);
    }
  });

  it('does not fire on look-alikes', async () => {
    const root = join(FIXTURES, 'lookalikes');
    const dirs: string[] = [];
    async function walk(dir: string): Promise<void> {
      const entries = await readdir(dir, { withFileTypes: true });
      if (entries.some((entry) => entry.name === 'SKILL.md')) dirs.push(dir);
      for (const entry of entries) {
        if (entry.isDirectory()) await walk(join(dir, entry.name));
      }
    }
    await walk(root);
    expect(dirs.length).toBeGreaterThan(10);
    const added = [
      'IH-FS-003',
      'IH-INJ-028',
      'IH-INJ-029',
      'IH-EXEC-012',
      'IH-EXEC-013',
      'IH-EXEC-014',
      'IH-EXEC-015',
      'IH-NET-009',
      'IH-NET-010',
    ];
    for (const dir of dirs) {
      const scanned = await scan(dir);
      expect(
        scanned.ids.filter((ruleId) => added.includes(ruleId)),
        dir,
      ).toEqual([]);
    }
  });

  it('keeps sudo apt-get install high on the adversarial twin', async () => {
    const prose = await scan(join(FIXTURES, 'adversarial/apt-get-prose'));
    expect(prose.verdict).toBe('block');
    expect(
      prose.findings
        .filter((finding) => finding.ruleId === 'IH-PRIV-001')
        .every((finding) => finding.severity === 'high'),
    ).toBe(true);

    const twin = await scan(join(FIXTURES, 'adversarial/apt-get-script'));
    expect(twin.verdict).toBe('block');
    const scriptLines = twin.findings.filter((finding) => finding.file.endsWith('setup.sh'));
    expect(scriptLines.length).toBe(2);
    expect(scriptLines.every((finding) => finding.severity === 'high')).toBe(true);

    const fenced = await scan(join(FIXTURES, 'adversarial/apt-get-fenced'));
    const fencedPriv = fenced.findings.filter((finding) => finding.ruleId === 'IH-PRIV-001');
    expect(fencedPriv.length).toBe(6);
    expect(fencedPriv.every((finding) => finding.severity === 'medium')).toBe(true);
  });
});
