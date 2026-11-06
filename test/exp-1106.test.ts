import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';
import { contentDigest } from '../src/mcp/receipts.ts';

const root = join(process.cwd(), 'bench/house');

async function ids(dir: string): Promise<string[]> {
  const result = await scanPath(dir, emptyConfig());
  return result.skills.flatMap((skill) => skill.findings.map((finding) => finding.ruleId));
}

async function verdict(dir: string): Promise<string> {
  const result = await scanPath(dir, emptyConfig());
  return result.skills[0]?.verdict ?? 'missing';
}

describe('2026-11-06 detection rules on house pairs', () => {
  const cases: Array<[string, string, string]> = [
    [
      'IH-BIN-003',
      'missed-2026-11-06/2026-11-06-path-shadow-system-binary/attack',
      'missed-2026-11-06/2026-11-06-path-shadow-system-binary/control',
    ],
    [
      'IH-BIN-003',
      'missed-2026-11-06/2026-11-06-path-shadow-system-binary/instruction/attack',
      'missed-2026-11-06/2026-11-06-path-shadow-system-binary/instruction/control',
    ],
    [
      'IH-EXEC-007',
      'missed-2026-11-06/2026-11-06-reverse-shell-as-debug-tunnel/attack',
      'missed-2026-11-06/2026-11-06-reverse-shell-as-debug-tunnel/control',
    ],
    [
      'IH-EXEC-007',
      'missed-2026-11-06/2026-11-06-reverse-shell-as-debug-tunnel/instruction/attack',
      'missed-2026-11-06/2026-11-06-reverse-shell-as-debug-tunnel/instruction/control',
    ],
    [
      'IH-INJ-012',
      'missed-2026-11-06/2026-11-03-silent-input-data-offset/attack',
      'missed-2026-11-06/2026-11-03-silent-input-data-offset/control',
    ],
    [
      'IH-REF-004',
      'missed-2026-11-06/2026-11-03-unseen-security-template/attack',
      'missed-2026-11-06/2026-11-03-unseen-security-template/control',
    ],
    [
      'IH-META-003',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/attack',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/control',
    ],
    [
      'IH-META-003',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/multistep/attack',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/multistep/twin',
    ],
    [
      'IH-META-003',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/reffile/attack',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/reffile/twin',
    ],
    [
      'IH-META-003',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/split/attack',
      'missed-2026-11-06/2026-11-03-skill-impersonation-deprecated-rival/variants/split/twin',
    ],
    [
      'IH-PERSIST-003',
      'missed-2026-11-06/2026-11-06-silent-self-replace/attack',
      'missed-2026-11-06/2026-11-06-silent-self-replace/control',
    ],
    [
      'IH-FS-002',
      'prose-variants-2026-11-03/persistence-control/ordinary/attack',
      'prose-variants-2026-11-03/persistence-control/ordinary/twin',
    ],
    [
      'IH-FS-002',
      'prose-variants-2026-11-03/persistence-control/reffile/attack',
      'prose-variants-2026-11-03/persistence-control/reffile/twin',
    ],
    [
      'IH-INJ-013',
      'prose-variants-2026-11-03/goal-memory-manipulation/ordinary/attack',
      'prose-variants-2026-11-03/goal-memory-manipulation/ordinary/twin',
    ],
    [
      'IH-INJ-013',
      'prose-variants-2026-11-03/goal-memory-manipulation/multistep/attack',
      'prose-variants-2026-11-03/goal-memory-manipulation/multistep/twin',
    ],
    [
      'IH-INJ-013',
      'prose-variants-2026-11-03/goal-memory-manipulation/reffile/attack',
      'prose-variants-2026-11-03/goal-memory-manipulation/reffile/twin',
    ],
  ];

  it.each(cases)('%s flags %s and not the twin', async (ruleId, attack, twin) => {
    const attackIds = await ids(join(root, attack));
    const twinIds = await ids(join(root, twin));
    expect(attackIds).toContain(ruleId);
    expect(twinIds).not.toContain(ruleId);
    expect(await verdict(join(root, attack))).toBe('review');
    expect(await verdict(join(root, twin))).toBe('no-findings');
  });
});

describe('IH-REF-001 weight and checksum', () => {
  it('does not treat a missing script or a script-only honest package as malicious', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-ref-'));
    await mkdir(join(dir, 'scripts'), { recursive: true });
    await writeFile(
      join(dir, 'SKILL.md'),
      '---\nname: demo\ndescription: Run the helper.\n---\n```bash\npython3 scripts/missing.py\npython3 scripts/ok.py\n```\n',
    );
    await writeFile(join(dir, 'scripts', 'ok.py'), 'print(1)\n');
    const result = await scanPath(dir, emptyConfig());
    const ref = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-REF-001');
    expect(ref.map((f) => f.severity)).toEqual(['medium']);
    expect(ref[0]?.message).toMatch(/Not checked/);
    expect(ref[0]?.message).toMatch(/scripts\/missing\.py/);
    // REF-001 stays context-only. A multi-file package that runs a missing local
    // script is incomplete (IH-META-005), not a clean pass and not a block.
    expect(result.skills[0]?.verdict).toBe('incomplete');
    expect(result.skills[0]?.findings.some((f) => f.ruleId === 'IH-META-005')).toBe(true);
    const digest = await contentDigest(dir);
    expect(digest.files['scripts/ok.py']).toMatch(/^[0-9a-f]{64}$/);
    expect(digest.files['scripts/missing.py']).toBeUndefined();
  });
});
