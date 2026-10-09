import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { contentRules } from '../src/rules/index.ts';
import { context, scannedFromFile } from './support.ts';

const root = join(process.cwd(), 'test/fixtures');

async function filesIn(dir: string): Promise<string[]> {
  const entries = await readdir(dir);
  return entries.filter((name) => !name.startsWith('.')).sort();
}

describe('detection rules', () => {
  for (const rule of contentRules) {
    it(`${rule.id} matches its positive fixtures and ignores near misses`, async () => {
      const positiveDir = join(root, 'malicious', rule.id);
      const negativeDir = join(root, 'benign', 'near', rule.id);
      const positives = await filesIn(positiveDir);
      const negatives = await filesIn(negativeDir);
      expect(positives.length).toBeGreaterThanOrEqual(3);
      expect(negatives.length).toBeGreaterThanOrEqual(3);

      for (const name of positives) {
        const relative = rule.id === 'IH-META-001' ? 'SKILL.md' : name;
        const file = await scannedFromFile(join(positiveDir, name), relative);
        if (rule.id === 'IH-BIN-001')
          file.text = new TextDecoder().decode(await readFile(join(positiveDir, name)));
        const findings = rule.check(file, context(undefined, 'expected'));
        expect(
          findings.some((finding) => finding.ruleId === rule.id),
          name,
        ).toBe(true);
        for (const finding of findings) {
          expect(finding.evidence.length).toBeLessThanOrEqual(200);
          expect(finding.evidence).not.toContain(String.fromCharCode(0x1b));
        }
      }

      for (const name of negatives) {
        const relative =
          rule.id === 'IH-META-001' && name.endsWith('.md') && name.startsWith('1')
            ? 'SKILL.md'
            : name;
        const file = await scannedFromFile(join(negativeDir, name), relative);
        const findings = rule.check(file, context(undefined, 'benign'));
        expect(findings, name).toEqual([]);
      }
    });
  }

  it('masks hard-coded secrets in evidence', async () => {
    const rule = contentRules.find((item) => item.id === 'IH-CRED-002');
    if (!rule) throw new Error('missing rule');
    const file = await scannedFromFile(join(root, 'malicious/IH-CRED-002/2.md'), '2.md');
    const findings = rule.check(file, context());
    expect(findings[0]?.evidence).toContain('AKIA');
    expect(findings[0]?.evidence).toContain('*');
    expect(findings[0]?.evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });
});
