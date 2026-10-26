import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { emptyConfig } from '../src/core/config.ts';
import { scanPath } from '../src/core/scanner.ts';
import { exec005 } from '../src/rules/ambient-env.ts';
import { context, scannedText } from './support.ts';

async function skillDir(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'ih-0150-'));
  for (const [name, text] of Object.entries(files)) {
    const path = join(root, name);
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, text);
  }
  return root;
}

const FM = '---\nname: demo\ndescription: Demo skill.\n---\n';

function ruleHits(name: string, text: string, skillHoldsSecret = false) {
  const ctx = context();
  if (skillHoldsSecret) ctx.skillHoldsSecret = true;
  return exec005.check(scannedText(name, text), ctx);
}

describe('0.15.0 IH-EXEC-005 ambient credential inheritance (calbrutower, aidroid, lilt, merktop)', () => {
  it('flags spawn with a full env spread when the same file names a key', () => {
    const found = ruleHits(
      'run.js',
      'const apiKey = process.env.OPENAI_API_KEY;\nspawn("node", ["server.js"], { env: { ...process.env, ...config.env } });\n',
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.ruleId).toBe('IH-EXEC-005');
    expect(found[0]?.severity).toBe('medium');
    expect(found[0]?.confidence).toBe('high');
    expect(found[0]?.line).toBe(2);
    expect(found[0]?.message).toContain('full parent environment');
    expect(found[0]?.message).toContain('secret');
    expect(found[0]?.remediation).toContain('PATH');
    expect(found[0]?.remediation).toContain('HOME');
  });

  it('flags a same-file spawn that omits env', () => {
    const found = ruleHits(
      'run.js',
      'const apiKey = process.env.OPENAI_API_KEY;\nspawn("node", ["helper.js"]);\n',
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain('without an env option');
    expect(found[0]?.confidence).toBe('medium');
    expect(found[0]?.line).toBe(2);
  });

  it('flags Python subprocess env=os.environ.copy()', () => {
    const found = ruleHits(
      'run.py',
      'key = os.environ["API_KEY"]\nsubprocess.run(["tool"], env=os.environ.copy())\n',
    );
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain('full parent environment');
  });

  it('stays quiet on an explicit allowlist that is not a full-env spread', () => {
    const text = [
      'spawn("node", ["server.js"], {',
      '  env: { PATH: process.env.PATH, HOME: process.env.HOME, OPENAI_API_KEY: process.env.OPENAI_API_KEY },',
      '});',
      '',
    ].join('\n');
    expect(ruleHits('run.js', text)).toEqual([]);
  });

  it('stays quiet on a dict comprehension that picks named keys', () => {
    const text =
      'env = {k: os.environ[k] for k in ("PATH", "HOME", "API_KEY")}\nsubprocess.run(["tool"], env=env)\n';
    expect(ruleHits('run.py', text)).toEqual([]);
    const filtered =
      'key = os.environ["API_KEY"]\nenv = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "API_KEY")}\nsubprocess.run(["tool"], env=env)\n';
    expect(ruleHits('run.py', filtered)).toEqual([]);
  });

  it('flags an unfiltered os.environ.items() copy and **os.environ', () => {
    const items =
      'key = os.environ["API_KEY"]\nenv = {k: v for k, v in os.environ.items()}\nsubprocess.run(["tool"], env=env)\n';
    expect(ruleHits('run.py', items)).toHaveLength(1);
    const spread =
      'key = os.environ["SECRET"]\nsubprocess.run(["tool"], env={**os.environ, "PATH": "/usr/bin"})\n';
    expect(ruleHits('run.py', spread)[0]?.message).toContain('full parent environment');
  });

  it('follows a same-file binding built from a full copy', () => {
    const js =
      'const apiKey = process.env.OPENAI_API_KEY;\nconst env = { ...process.env };\nspawn("node", ["helper.js"], { env });\n';
    expect(ruleHits('run.js', js)).toHaveLength(1);
    const py =
      'key = os.environ.get("API_KEY")\nenv = os.environ.copy()\nsubprocess.run(["tool"], env=env)\n';
    expect(ruleHits('run.py', py)).toHaveLength(1);
    const bare =
      'const apiKey = process.env.OPENAI_API_KEY;\nspawn("node", ["h.js"], { env: process.env });\n';
    expect(ruleHits('run.js', bare)[0]?.message).toContain('full parent environment');
  });

  it('reports one finding per file and prefers the explicit full copy', () => {
    const text = [
      'const apiKey = process.env.OPENAI_API_KEY;',
      'spawn("node", ["a.js"]);',
      'spawn("node", ["b.js"], { env: { ...process.env } });',
      '',
    ].join('\n');
    const found = ruleHits('run.js', text);
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(3);
    expect(found[0]?.message).toContain('full parent environment');
  });

  it('does not treat regex.exec or a commented call as a child process', () => {
    expect(
      ruleHits(
        'run.js',
        'const apiKey = process.env.OPENAI_API_KEY;\nconst match = /x/.exec(line);\n',
      ),
    ).toEqual([]);
    expect(
      ruleHits(
        'run.js',
        'const apiKey = process.env.OPENAI_API_KEY;\n// spawn("node", ["x"], { env: { ...process.env } });\nconsole.log(apiKey);\n',
      ),
    ).toEqual([]);
    expect(
      ruleHits(
        'run.py',
        'key = os.environ["API_KEY"]\n# subprocess.run(["tool"], env=os.environ.copy())\nprint(key)\n',
      ),
    ).toEqual([]);
  });

  it('does not flag a call that only appears inside a string or a Python docstring', () => {
    const text =
      'const apiKey = process.env.OPENAI_API_KEY;\nconst note = "spawn(\'x\', { env: { ...process.env } })";\nconsole.log(apiKey, note);\n';
    expect(ruleHits('run.js', text)).toEqual([]);
    const docstring =
      'key = os.environ["API_KEY"]\n"""\nsubprocess.run(["tool"], env=os.environ.copy())\n"""\nprint(key)\n';
    expect(ruleHits('run.py', docstring)).toEqual([]);
  });

  it('still sees a real spawn after an escaped quote', () => {
    const text =
      'const apiKey = process.env.OPENAI_API_KEY;\nconst note = "he said \\"hi\\"";\nspawn("node", ["helper.js"]);\n';
    expect(ruleHits('run.js', text)).toHaveLength(1);
  });

  it('treats dict(os.environ), environ.copy(), Deno.env.toObject(), and env=None as inheritance', () => {
    expect(
      ruleHits(
        'run.py',
        'key = os.environ["API_KEY"]\nsubprocess.run(["tool"], env=dict(os.environ))\n',
      )[0]?.message,
    ).toContain('full parent environment');
    expect(
      ruleHits(
        'run.py',
        'key = os.environ["API_KEY"]\nenv = environ.copy()\nsubprocess.run(["tool"], env=env)\n',
      ),
    ).toHaveLength(1);
    expect(
      ruleHits(
        'run.js',
        'const apiKey = process.env.OPENAI_API_KEY;\nnew Deno.Command("tool", { env: Deno.env.toObject() });\n',
      )[0]?.message,
    ).toContain('full parent environment');
    expect(
      ruleHits('run.py', 'key = os.environ["API_KEY"]\nsubprocess.run(["tool"], env=None)\n')[0]
        ?.message,
    ).toContain('without an env option');
  });

  it('does not treat a function named spawn as a child process', () => {
    expect(
      ruleHits(
        'run.js',
        'const apiKey = process.env.OPENAI_API_KEY;\nfunction spawn(cmd) { return cmd; }\nconsole.log(apiKey);\n',
      ),
    ).toEqual([]);
  });

  it('flags child_process.spawn and fork, and skips tests/ even when a key is present', () => {
    expect(
      ruleHits(
        'run.js',
        'const apiKey = process.env.OPENAI_API_KEY;\nchild_process.spawn("node", ["helper.js"]);\n',
      ),
    ).toHaveLength(1);
    expect(
      ruleHits('run.js', 'const apiKey = process.env.OPENAI_API_KEY;\nfork("./worker.js");\n'),
    ).toHaveLength(1);
    expect(
      ruleHits(
        'tests/spawn.js',
        'const apiKey = process.env.OPENAI_API_KEY;\nspawn("node", ["s.js"], { env: { ...process.env } });\n',
      ),
    ).toEqual([]);
  });

  it('flags a full-env spawn when the key is in another file of the skill', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}\nRead OPENAI_API_KEY from the environment.\n`,
      'scripts/run.js':
        'import { spawn } from "node:child_process";\nspawn("node", ["server.js"], { env: { ...process.env, ...config.env } });\n',
    });
    const result = await scanPath(root, emptyConfig());
    const hits = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-EXEC-005');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.file).toBe('scripts/run.js');
    expect(hits[0]?.message).toContain('full parent environment');
    expect(result.verdict).toBe('review');
  });

  it('does not flag a default inherit in another file when only the skill names the key', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}\nThe helper needs OPENAI_API_KEY.\n`,
      'scripts/run.js':
        'import { spawn } from "node:child_process";\nspawn("node", ["helper.js"]);\n',
    });
    const result = await scanPath(root, emptyConfig());
    const hits = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-EXEC-005');
    expect(hits).toEqual([]);
    expect(result.verdict).toBe('no-findings');
  });

  it('stays quiet when the skill names no secret', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}\nRun the helper.\n`,
      'scripts/run.js':
        'import { spawn } from "node:child_process";\nspawn("node", ["server.js"], { env: { ...process.env } });\nspawn("node", ["other.js"]);\n',
    });
    const result = await scanPath(root, emptyConfig());
    const hits = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-EXEC-005');
    expect(hits).toEqual([]);
    expect(result.verdict).toBe('no-findings');
  });

  it('does not let a key that exists only under tests/ light up a full-env spawn', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}\nRun the helper.\n`,
      'src/run.js': 'spawn("node", ["server.js"], { env: { ...process.env } });\n',
      'tests/fake.js': 'const apiKey = process.env.OPENAI_API_KEY;\n',
    });
    const result = await scanPath(root, emptyConfig());
    const hits = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-EXEC-005');
    expect(hits).toEqual([]);
  });

  it('scans an allowlist skill as no-findings', async () => {
    const root = await skillDir({
      'SKILL.md': `${FM}\n# Helper\n`,
      'run.js':
        'spawn("node", ["server.js"], { env: { PATH: process.env.PATH, HOME: process.env.HOME, OPENAI_API_KEY: process.env.OPENAI_API_KEY } });\n',
    });
    const result = await scanPath(root, emptyConfig());
    const hits = result.skills
      .flatMap((skill) => skill.findings)
      .filter((f) => f.ruleId === 'IH-EXEC-005');
    expect(hits).toEqual([]);
    expect(result.verdict).toBe('no-findings');
  });
});
