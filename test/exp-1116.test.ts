import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { gradeFromSkills } from '../src/core/grade.ts';
import { scanPath } from '../src/core/scanner.ts';
import type { Finding } from '../src/core/types.ts';
import { scoreFindings, verdictFor } from '../src/core/verdict.ts';
import { SHADOW_CHECKS } from '../src/rules/shadow.ts';

const root = join(process.cwd(), 'bench/house/missed-2026-11-06');
const controls = join(process.cwd(), 'test/fixtures/benign/near/IH-INJ-016');

beforeAll(() => {
  process.env.IRONHEIGHTS_SHADOW = 'enforce';
});

afterAll(() => {
  delete process.env.IRONHEIGHTS_SHADOW;
});

async function report(dir: string) {
  const result = await scanPath(dir, emptyConfig());
  const skill = result.skills[0];
  return {
    verdict: skill?.verdict ?? 'missing',
    ids: result.skills.flatMap((item) => item.findings.map((finding) => finding.ruleId)),
    findings: result.skills.flatMap((item) => item.findings),
    skill,
  };
}

function finding(partial: Partial<Finding> & Pick<Finding, 'ruleId' | 'severity'>): Finding {
  return {
    confidence: 'medium',
    file: 'SKILL.md',
    evidence: 'evidence',
    message: 'message',
    remediation: 'fix',
    ...partial,
  };
}

describe('2026-11-06 four-idea rules', () => {
  it('blocks an unlisted payee change and does not block the honest invoice twin', async () => {
    const attack = await report(join(root, '2026-11-06-unlisted-payee/attack'));
    const twin = await report(join(root, '2026-11-06-unlisted-payee/control'));
    expect(attack.ids).toContain('IH-INJ-014');
    expect(attack.verdict).toBe('block');
    expect(twin.ids).not.toContain('IH-INJ-014');
    expect(twin.ids).not.toContain('IH-INJ-015');
    expect(twin.verdict).toBe('no-findings');
  });

  it('reviews an unlisted non-payment edit and does not block on it', async () => {
    const ordinary = await report(join(root, '2026-11-06-unlisted-payee/ordinary'));
    expect(ordinary.ids).toContain('IH-INJ-015');
    expect(ordinary.ids).not.toContain('IH-INJ-014');
    expect(ordinary.verdict).toBe('review');
    const hit = ordinary.findings.find((item) => item.ruleId === 'IH-INJ-015');
    expect(hit?.scoreExempt).toBe(true);
    expect(hit?.severity).toBe('medium');
  });

  it('does not treat the word payment, or a declared env key, as the attack', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-pay-'));
    await writeFile(
      join(dir, 'SKILL.md'),
      [
        '---',
        'name: invoice-helper',
        'description: Explain payment terms.',
        '---',
        '',
        'Summarize the payment terms on the invoice the user provides.',
        'Read the payee and the amount and tell the user what you found.',
        'Do not change the payee.',
        '',
        'Read the user-declared environment variable ACME_API_KEY.',
        'The user sets that slot. Tell the user you are using ACME_API_KEY.',
        'The key does not prove who the agent is.',
        '',
      ].join('\n'),
    );
    const scanned = await report(dir);
    expect(scanned.ids).not.toContain('IH-INJ-014');
    expect(scanned.ids).not.toContain('IH-INJ-015');
    expect(scanned.ids).not.toContain('IH-CRED-007');
    expect(scanned.verdict).toBe('no-findings');
  });

  it('reviews a memory key used as identity and not a declared slot', async () => {
    const attack = await report(join(root, '2026-11-06-memory-api-key/attack'));
    const twin = await report(join(root, '2026-11-06-memory-api-key/control'));
    expect(attack.ids).toContain('IH-CRED-007');
    expect(attack.verdict).toBe('review');
    expect(attack.findings.find((item) => item.ruleId === 'IH-CRED-007')?.scoreExempt).toBe(true);
    expect(twin.ids).not.toContain('IH-CRED-007');
    expect(twin.verdict).toBe('no-findings');
  });

  it('reviews third-party principal instructions and leaves the honest grant alone', async () => {
    const attack = await report(join(root, '2026-11-06-third-party-principal/attack'));
    const twin = await report(join(root, '2026-11-06-third-party-principal/control'));
    expect(attack.ids).toContain('IH-INJ-016');
    expect(attack.verdict).toBe('review');
    expect(twin.ids).not.toContain('IH-INJ-016');
    expect(twin.verdict).toBe('no-findings');
  });

  it.each(['1.md', '2.md', '3.md', '4.md', '5.md', '6.md', '7.md'])(
    'does not flag honest authority shape %s',
    async (name) => {
      const dir = await mkdtemp(join(tmpdir(), 'ih-grant-'));
      await writeFile(join(dir, 'SKILL.md'), await readFile(join(controls, name)));
      const scanned = await report(dir);
      expect(scanned.ids).not.toContain('IH-INJ-016');
      expect(scanned.ids).not.toContain('IH-META-004');
      expect(scanned.ids).not.toContain('IH-META-005');
      expect(scanned.verdict).toBe('no-findings');
    },
  );

  it('notes a stub that contradicts an honest grant without blaming the license', async () => {
    const scanned = await report(join(root, '2026-11-06-third-party-principal/stub'));
    expect(scanned.ids).not.toContain('IH-INJ-016');
    expect(scanned.ids).toContain('IH-META-004');
    expect(scanned.ids).toContain('IH-EXEC-001');
    const note = scanned.findings.find((item) => item.ruleId === 'IH-META-004');
    expect(note?.severity).toBe('info');
    expect(note?.message).toMatch(/does not block the honest language/);
    expect(note?.file).toBe('scripts/run.py');
    expect(scanned.verdict).toBe('block');
  });

  it('marks incomplete packages incomplete and leaves honest docs clean', async () => {
    const missingSkill = await report(join(root, '2026-11-06-rebuildable/missing-skill'));
    const stub = await report(join(root, '2026-11-06-rebuildable/meta-stub'));
    const missingScript = await report(join(root, '2026-11-06-rebuildable/missing-script'));
    const honest = await report(join(root, '2026-11-06-rebuildable/honest-docs'));
    const shipped = await report(join(root, '2026-11-06-rebuildable/shipped'));
    for (const scanned of [missingSkill, stub, missingScript]) {
      expect(scanned.ids).toContain('IH-META-005');
      expect(scanned.verdict).toBe('incomplete');
    }
    // No other risk points: the grade is incomplete, not an A.
    expect(gradeFromSkills(missingSkill.skill ? [missingSkill.skill] : []).letter).toBe(
      'incomplete',
    );
    expect(gradeFromSkills(stub.skill ? [stub.skill] : []).letter).toBe('incomplete');
    // The missing script still carries the IH-REF-001 grade points. The verdict is incomplete.
    expect(gradeFromSkills(missingScript.skill ? [missingScript.skill] : []).letter).not.toBe('A');
    expect(honest.ids).not.toContain('IH-META-005');
    expect(honest.verdict).toBe('no-findings');
    expect(shipped.ids).not.toContain('IH-META-005');
    expect(shipped.verdict).toBe('no-findings');
  });

  it('keeps a one-file script mention at the coverage note', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-one-'));
    await writeFile(
      join(dir, 'SKILL.md'),
      '---\nname: demo\ndescription: Run the helper.\n---\n```bash\npython3 scripts/apply.py\n```\n',
    );
    const scanned = await report(dir);
    expect(scanned.ids).toContain('IH-REF-001');
    expect(scanned.ids).not.toContain('IH-META-005');
    expect(scanned.verdict).toBe('no-findings');
  });

  it('does not let a review-tier finding supply the points that cross the block line', () => {
    const held = [
      finding({ ruleId: 'IH-CRED-001', severity: 'medium' }),
      finding({ ruleId: 'IH-CRED-001', severity: 'medium' }),
      finding({ ruleId: 'IH-CRED-001', severity: 'medium' }),
      finding({ ruleId: 'IH-CRED-001', severity: 'medium' }),
      finding({ ruleId: 'IH-CRED-001', severity: 'medium' }),
      finding({ ruleId: 'IH-INJ-015', severity: 'medium', scoreExempt: true }),
    ];
    expect(scoreFindings(held)).toBe(75);
    expect(verdictFor(held, { block: 80, review: 15 })).toBe('review');
    expect(
      verdictFor([finding({ ruleId: 'IH-INJ-014', severity: 'critical' })], {
        block: 80,
        review: 15,
      }),
    ).toBe('block');
  });

  it('logs a shadowed payee hit without changing the verdict', async () => {
    const previous = process.env.IRONHEIGHTS_SHADOW;
    delete process.env.IRONHEIGHTS_SHADOW;
    try {
      const attack = await report(join(root, '2026-11-06-unlisted-payee/attack'));
      const hit = attack.findings.find((item) => item.ruleId === 'IH-INJ-014');
      if (SHADOW_CHECKS.has('unlisted-payee')) {
        expect(hit?.severity).toBe('info');
        expect(hit?.wouldSeverity).toBe('critical');
        expect(attack.verdict).toBe('no-findings');
      } else {
        expect(hit?.severity).toBe('critical');
        expect(attack.verdict).toBe('block');
      }
    } finally {
      if (previous === undefined) delete process.env.IRONHEIGHTS_SHADOW;
      else process.env.IRONHEIGHTS_SHADOW = previous;
    }
  });
});

describe('allow-skipped does not clear a rebuildable gap', () => {
  it('stays incomplete', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-stub-'));
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, 'SKILL.md'),
      '---\nname: placeholder\ndescription: Placeholder gist.\n---\n\nThis gist is a placeholder. No concrete skill text.\n',
    );
    const result = await scanPath(dir, emptyConfig(), { allowSkipped: true });
    expect(result.skills[0]?.verdict).toBe('incomplete');
    expect(result.verdict).toBe('incomplete');
  });
});
