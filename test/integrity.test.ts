import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import {
  baselineIsTampered,
  createBaseline,
  parseBaseline,
  writeBaseline,
} from '../src/integrity/baseline.ts';
import { quarantineSkill, restoreQuarantine } from '../src/integrity/quarantine.ts';
import { verifyBaseline, saveBaseline } from '../src/integrity/verify.ts';
import { scoreFindings, verdictFor } from '../src/core/verdict.ts';

describe('integrity', () => {
  it('reports added, modified, removed, mode-changed, and tampered baselines', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-base-'));
    const skill = join(dir, 'skill');
    await mkdir(skill);
    const file = join(skill, 'SKILL.md');
    await writeFile(file, '---\nname: skill\ndescription: Demo.\n---\nhello\n');
    const home = join(dir, 'home');
    const config = emptyConfig({ skillDirs: [skill], agentFiles: [] });
    await saveBaseline(config, home, new Date('2026-10-09T00:00:00.000Z'));
    const clean = await verifyBaseline(config, home);
    expect(clean.baselineTampered).toBe(false);
    expect(clean.findings).toEqual([]);

    await writeFile(file, '---\nname: skill\ndescription: Demo.\n---\nchanged\n');
    const modified = await verifyBaseline(config, home);
    expect(modified.modified).toHaveLength(1);
    expect(modified.findings.some((item) => item.ruleId === 'IH-INT-001')).toBe(true);

    await writeFile(file, '---\nname: skill\ndescription: Demo.\n---\nhello\n');
    const created = await createBaseline([skill]);
    await writeBaseline(join(home, 'baseline.json'), created);
    await chmod(file, 0o600);
    const mode = await verifyBaseline(config, home);
    expect(mode.modeChanged.length).toBe(1);

    await chmod(file, 0o644);
    const again = await createBaseline([skill]);
    await writeBaseline(join(home, 'baseline.json'), again);
    await writeFile(join(skill, 'extra.md'), 'new file\n');
    const added = await verifyBaseline(config, home);
    expect(added.added.length).toBe(1);
    expect(added.findings.some((item) => item.ruleId === 'IH-INT-002')).toBe(true);

    await writeFile(join(home, 'baseline.json'), JSON.stringify(again, null, 2));
    await rm(join(skill, 'extra.md'));
    await writeFile(join(skill, 'gone.md'), 'bye\n');
    const withGone = await createBaseline([skill]);
    await writeBaseline(join(home, 'baseline.json'), withGone);
    await rm(join(skill, 'gone.md'));
    const removed = await verifyBaseline(config, home);
    expect(removed.removed.length).toBe(1);
    expect(removed.findings.some((item) => item.ruleId === 'IH-INT-003')).toBe(true);

    const saved = parseBaseline(await readFile(join(home, 'baseline.json'), 'utf8'));
    saved.treeHash = '0'.repeat(64);
    await writeBaseline(join(home, 'baseline.json'), saved);
    expect(baselineIsTampered(saved)).toBe(true);
    const tampered = await verifyBaseline(config, home);
    expect(tampered.baselineTampered).toBe(true);
    expect(tampered.findings.some((item) => item.message.includes('treeHash'))).toBe(true);
    expect(verdictFor(tampered.findings, config.thresholds)).not.toBe('no-findings');
    expect(scoreFindings(tampered.findings)).toBeGreaterThan(0);
  });

  it('flags a watched agent file as IH-INT-004', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-agent-'));
    const agent = join(dir, 'AGENTS.md');
    await writeFile(agent, 'hello\n');
    const home = join(dir, 'home');
    const config = emptyConfig({ skillDirs: [], agentFiles: [agent] });
    await saveBaseline(config, home);
    await writeFile(agent, 'changed\n');
    const result = await verifyBaseline(config, home);
    expect(result.findings.some((item) => item.ruleId === 'IH-INT-004')).toBe(true);
  });
});

describe('quarantine', () => {
  it('round-trips a skill without data loss', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-quar-'));
    const skill = join(dir, 'demo-skill');
    await mkdir(skill);
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: demo-skill\ndescription: Demo.\n---\nkeep\n',
    );
    await writeFile(join(skill, 'notes.txt'), 'same bytes\n');
    const home = join(dir, 'home');
    const manifest = await quarantineSkill(skill, home, new Date('2026-10-09T00:00:00.000Z'));
    await expect(readFile(skill, 'utf8')).rejects.toThrow();
    const restored = await restoreQuarantine(manifest.id, home);
    expect(restored.originalPath).toBe(skill);
    expect(await readFile(join(skill, 'notes.txt'), 'utf8')).toBe('same bytes\n');
    expect(await readFile(join(skill, 'SKILL.md'), 'utf8')).toContain('keep');
  });
});
