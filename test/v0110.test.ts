import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { formatGrade, gradeFromSkills } from '../src/core/grade.ts';
import { scanPath } from '../src/core/scanner.ts';
import { staysInsideSkill } from '../src/rules/filesystem.ts';
import { negatedSudoOnly } from '../src/rules/privilege.ts';

async function skillDir(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'ih-0110-'));
  for (const [name, text] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, text);
  }
  return root;
}

const SKILL = '---\nname: demo\ndescription: Demo skill.\n---\n# Demo\n';

function rules(result: Awaited<ReturnType<typeof scanPath>>, id: string) {
  return result.skills.flatMap((s) => s.findings).filter((f) => f.ruleId === id);
}

describe('0.11.0: relative paths inside the skill folder', () => {
  it('allows ../ that resolves inside the skill', () => {
    expect(staysInsideSkill('see ../references/api.md', 'scripts/run.sh')).toBe(true);
    expect(staysInsideSkill('cat ../../shared/x.md', 'a/b/c.sh')).toBe(true);
  });
  it('keeps paths that leave the skill', () => {
    expect(staysInsideSkill('cat ../references/api.md', 'SKILL.md')).toBe(false);
    expect(staysInsideSkill('cat ../../../etc/passwd', 'scripts/run.sh')).toBe(false);
    expect(staysInsideSkill('type ..\\..\\secret', 'scripts/run.sh')).toBe(false);
    expect(staysInsideSkill('cp ../ok.md ../../../../x', 'a/b.sh')).toBe(false);
  });
  it('end to end: inside quiet, outside flagged', async () => {
    const root = await skillDir({
      'SKILL.md': SKILL,
      'scripts/run.sh': 'cat ../references/api.md\n',
      'scripts/bad.sh': 'cat ../../../../etc/passwd\n',
      'references/api.md': '# API\n',
    });
    const fs = rules(await scanPath(root, emptyConfig()), 'IH-FS-001');
    expect(fs.map((f) => f.file)).toEqual(['scripts/bad.sh']);
  });
});

describe('0.11.0: advice against sudo', () => {
  it.each([
    'Never use sudo with this installer.',
    "Don't run this with sudo.",
    'Do not use `sudo` here.',
    'No sudo needed.',
    'sudo is not required.',
    'Avoid sudo.',
  ])('quiet: %s', (line) => expect(negatedSudoOnly(line)).toBe(true));
  it.each([
    'sudo bash install.sh',
    'Never use sudo; instead run sudo chmod 777 /usr/local',
    "Don't worry, just run sudo make install",
    'Never use sudo. chmod 777 ./bin',
  ])('flagged: %s', (line) => expect(negatedSudoOnly(line)).toBe(false));
  it('end to end', async () => {
    const root = await skillDir({
      'SKILL.md': `${SKILL}\nNever use sudo to install this skill.\n`,
    });
    expect(rules(await scanPath(root, emptyConfig()), 'IH-PRIV-001')).toEqual([]);
  });
});

describe('0.11.0: registry skill card is notes', () => {
  it('demotes findings in skill-card.md to info', async () => {
    const root = await skillDir({
      'SKILL.md': SKILL,
      'skill-card.md': '# Card\n\nWarning: this skill runs sudo bash install.sh\n',
    });
    const result = await scanPath(root, emptyConfig());
    const card = result.skills.flatMap((s) => s.findings).filter((f) => f.file === 'skill-card.md');
    expect(card.length).toBeGreaterThan(0);
    for (const f of card) expect(f.severity).toBe('info');
  });
  it('a skill-card.md deeper in the tree is still graded as code', async () => {
    const root = await skillDir({
      'SKILL.md': SKILL,
      'lib/skill-card.md': 'sudo bash install.sh\n',
    });
    const f = rules(await scanPath(root, emptyConfig()), 'IH-PRIV-001');
    expect(f[0]?.severity).toBe('high');
  });
});

describe('0.11.0: empty folder', () => {
  it('reports nothing scanned instead of an A', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-0110-empty-'));
    const result = await scanPath(root, emptyConfig());
    const grade = gradeFromSkills(result.skills);
    expect(grade.letter).toBe('nothing-scanned');
    expect(formatGrade(grade)).toBe('nothing scanned');
  });
  it('a real skill still gets a letter', async () => {
    const root = await skillDir({ 'SKILL.md': SKILL });
    expect(gradeFromSkills((await scanPath(root, emptyConfig())).skills).letter).toBe('A');
  });
});
