import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import AjvDraft04 from 'ajv-draft-04';
import { describe, expect, it } from 'vitest';
import { isDirectInvocation, main } from '../src/cli/index.ts';
import { nodeMeetsOpenClaw, runDoctor } from '../src/cli/commands/doctor.ts';
import { renderSarif } from '../src/cli/output/sarif.ts';
import { locateOpenClaw, parseJson5 } from '../src/openclaw/locate.ts';

const SarifAjv = AjvDraft04 as unknown as new (options: {
  allErrors: boolean;
  strict: boolean;
}) => {
  compile: (schema: object) => ((data: unknown) => boolean) & { errors?: unknown };
};

describe('direct invocation', () => {
  it('recognizes a bin symlink and a relative shim path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-entry-'));
    try {
      const file = join(dir, 'index.js');
      await writeFile(file, '');
      const link = join(dir, 'ironheights');
      await symlink(file, link);
      const bin = join(dir, 'bin');
      await mkdir(bin);
      const moduleUrl = pathToFileURL(file).href;
      expect(isDirectInvocation(moduleUrl, file)).toBe(true);
      expect(isDirectInvocation(moduleUrl, link)).toBe(true);
      expect(isDirectInvocation(moduleUrl, join(bin, '..', 'index.js'))).toBe(true);
      expect(isDirectInvocation(moduleUrl, undefined)).toBe(false);
      expect(isDirectInvocation(moduleUrl, '')).toBe(false);
      expect(isDirectInvocation(moduleUrl, join(dir, 'missing.js'))).toBe(false);
      await writeFile(join(dir, 'other.js'), '');
      expect(isDirectInvocation(moduleUrl, join(dir, 'other.js'))).toBe(false);
      expect(isDirectInvocation('not-a-url', file)).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('cli', () => {
  it('scans a benign folder and returns exit code 0', async () => {
    const lines: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      const code = await main(['scan', 'test/fixtures/benign', '--no-color']);
      expect(code).toBe(0);
      expect(lines.join('')).toContain('No findings');
    } finally {
      process.stdout.write = original;
    }
  });

  it('returns 64 for a missing path and stubs --online', async () => {
    const code = await main(['scan', 'test/fixtures/does-not-exist']);
    expect(code).toBe(64);
    const online = await main(['--online', 'scan', 'test/fixtures/benign']);
    expect(online).toBe(0);
  });

  it('uses --fail-on', async () => {
    const code = await main([
      'scan',
      'test/fixtures/malicious/IH-CRED-001',
      '--fail-on',
      'critical',
      '--json',
    ]);
    expect(code).toBe(0);
    const blocked = await main(['scan', 'test/fixtures/malicious/IH-EXEC-001', '--json']);
    expect(blocked).toBe(2);
  });
});

describe('doctor and locate', () => {
  it('reports found and missing OpenClaw paths', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-oc-'));
    const state = join(dir, 'state');
    const workspace = join(dir, 'workspace');
    await mkdir(join(workspace, 'skills'), { recursive: true });
    await mkdir(join(state, 'agents', 'main', 'agent'), { recursive: true });
    await writeFile(
      join(state, 'openclaw.json'),
      '{ /* comment */ agents: { defaults: { workspace: "' +
        workspace +
        '", }, }, skills: { load: { extraDirs: [], }, }, }\n',
    );
    const located = await locateOpenClaw({
      OPENCLAW_STATE_DIR: state,
      OPENCLAW_CONFIG_PATH: join(state, 'openclaw.json'),
    });
    expect(located.configFound).toBe(true);
    expect(located.configParsed).toBe(true);
    expect(located.workspace).toBe(workspace);
    expect(
      located.skillDirs.some((item) => item.exists && item.source === 'workspace skills'),
    ).toBe(true);
    expect(located.skillDirs.some((item) => !item.exists)).toBe(true);
    const lines: string[] = [];
    const code = await runDoctor({
      env: {
        OPENCLAW_STATE_DIR: state,
        OPENCLAW_CONFIG_PATH: join(state, 'openclaw.json'),
        IRONHEIGHTS_HOME: dir,
      },
      stdout: (text) => lines.push(text),
    });
    expect(code).toBe(0);
    expect(lines.join('')).toContain('found');
    expect(lines.join('')).toContain('missing');
    expect(nodeMeetsOpenClaw('v24.16.0')).toBe(true);
    expect(nodeMeetsOpenClaw('v22.12.0')).toBe(false);
    expect(nodeMeetsOpenClaw('v26.1.0')).toBe(true);
    expect(nodeMeetsOpenClaw('v25.0.0')).toBe(false);
    expect(parseJson5('{a:1,}')).toEqual({ a: 1 });
  });
});

describe('sarif schema', () => {
  it('validates against the official SARIF 2.1.0 schema', async () => {
    const schema = JSON.parse(
      await readFile(join(process.cwd(), 'test/sarif-schema-2.1.0.json'), 'utf8'),
    ) as object;
    const ajv = new SarifAjv({ allErrors: true, strict: false });
    const validate = ajv.compile(schema);
    const doc = JSON.parse(
      renderSarif([
        {
          skillName: 'demo',
          root: '/tmp/demo',
          filesScanned: 1,
          filesSkipped: [],
          score: 40,
          verdict: 'review',
          findings: [
            {
              ruleId: 'IH-CRED-001',
              severity: 'high',
              confidence: 'high',
              file: 'SKILL.md',
              line: 2,
              evidence: 'example',
              message: 'example',
              remediation: 'fix',
            },
          ],
        },
      ]),
    ) as unknown;
    expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
  });
});
