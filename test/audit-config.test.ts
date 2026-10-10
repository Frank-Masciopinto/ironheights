import { chmod, lstat, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runAuditConfig } from '../src/cli/commands/audit-config.ts';
import { main } from '../src/cli/index.ts';
import { linkPath } from './support.ts';

const BENIGN = `{
  // local gateway, secret stays in the environment
  gateway: {
    mode: "local",
    bind: "loopback",
    auth: { mode: "token", token: "\${OPENCLAW_GATEWAY_TOKEN}" },
  },
  tools: {
    exec: { security: "deny", ask: "always" },
    elevated: { enabled: false },
  },
  channels: {
    telegram: { dmPolicy: "pairing", groupPolicy: "allowlist" },
  },
  agents: { defaults: { sandbox: { mode: "all" } } },
}
`;

const SECRET = 'ih-super-secret-token-value';

const EXPOSED = `{
  gateway: {
    bind: "lan",
    auth: { mode: "none" },
    tailscale: { mode: "funnel" },
    customBindHost: "0.0.0.0",
  },
  tools: {
    exec: { security: "full", ask: "off" },
    elevated: { enabled: true, allowFrom: { telegram: ["*"] } },
  },
  channels: {
    telegram: { dmPolicy: "open", allowFrom: ["*"], groupPolicy: "open" },
  },
  skills: { load: { extraDirs: ["~", "~/Projects/skills"], allowSymlinkTargets: ["/"] } },
  agents: { defaults: { sandbox: { mode: "off", docker: { image: "sandbox" } } } },
  hooks: { token: "${SECRET}" },
}
`;

async function writeConfig(dir: string, body: string, mode = 0o600): Promise<string> {
  const state = join(dir, 'state');
  await mkdir(state, { recursive: true });
  const configPath = join(state, 'openclaw.json');
  await writeFile(configPath, body);
  await chmod(configPath, mode);
  return configPath;
}

function envFor(dir: string, configPath: string): NodeJS.ProcessEnv {
  return {
    OPENCLAW_STATE_DIR: join(dir, 'state'),
    OPENCLAW_CONFIG_PATH: configPath,
    HOME: dir,
    USERPROFILE: dir,
  };
}

describe('audit-config', () => {
  it('stays quiet for a loopback config that keeps the token in the environment', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-ok-'));
    const configPath = await writeConfig(dir, BENIGN);
    const lines: string[] = [];
    const code = await runAuditConfig({
      json: true,
      env: envFor(dir, configPath),
      stdout: (text) => lines.push(text),
      now: new Date('2026-10-10T00:00:00.000Z'),
    });
    const payload = JSON.parse(lines.join('')) as {
      schemaVersion: number;
      command: string;
      verdict: string;
      configFound: boolean;
      skills: Array<{ findings: Array<{ ruleId: string; evidence: string }> }>;
      limits: string[];
    };
    expect(code).toBe(0);
    expect(payload.schemaVersion).toBe(1);
    expect(payload.command).toBe('audit-config');
    expect(payload.verdict).toBe('no-findings');
    expect(payload.configFound).toBe(true);
    expect(payload.skills[0]?.findings).toEqual([]);
    expect(payload.limits.join('\n')).toContain('openclaw security audit');
    expect(lines.join('')).not.toContain('OPENCLAW_GATEWAY_TOKEN=');
    await rm(dir, { recursive: true, force: true });
  });

  it('reports exposed settings and redacts literal secrets', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-bad-'));
    const configPath = await writeConfig(dir, EXPOSED, 0o644);
    const lines: string[] = [];
    const code = await runAuditConfig({
      json: true,
      env: envFor(dir, configPath),
      stdout: (text) => lines.push(text),
    });
    const text = lines.join('');
    const payload = JSON.parse(text) as {
      verdict: string;
      skills: Array<{ findings: Array<{ ruleId: string; evidence: string; severity: string }> }>;
    };
    const findings = payload.skills[0]?.findings ?? [];
    const ids = new Set(findings.map((finding) => finding.ruleId));
    expect(code).toBe(2);
    expect(payload.verdict).toBe('block');
    for (const id of [
      'IH-CFG-001',
      'IH-CFG-002',
      'IH-CFG-003',
      'IH-CFG-004',
      'IH-CFG-005',
      'IH-CFG-007',
      'IH-CFG-008',
      'IH-CFG-009',
    ]) {
      expect(ids.has(id), id).toBe(true);
    }
    if (process.platform === 'win32') expect(ids.has('IH-CFG-006')).toBe(false);
    else expect(ids.has('IH-CFG-006')).toBe(true);
    expect(text).not.toContain(SECRET);
    expect(text).toContain('<redacted>');
    const broad = findings.find(
      (finding) => finding.ruleId === 'IH-CFG-008' && finding.evidence.includes('extraDirs=~'),
    );
    expect(broad?.severity).toBe('critical');
    await rm(dir, { recursive: true, force: true });
  });

  it('uses fail-on and returns 3 when the config cannot be parsed', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-exit-'));
    const medium = await writeConfig(
      dir,
      `{
        gateway: { bind: "loopback", auth: { mode: "token", token: "\${OPENCLAW_GATEWAY_TOKEN}" } },
        tools: { exec: { security: "deny", ask: "always" }, elevated: { enabled: false } },
        skills: { load: { extraDirs: ["~/Projects/skills"] } },
        agents: { defaults: { sandbox: { mode: "all" } } },
      }
      `,
    );
    const quiet = await runAuditConfig({
      env: envFor(dir, medium),
      failOn: 'critical',
      stdout: () => undefined,
    });
    expect(quiet).toBe(0);
    const review = await runAuditConfig({
      env: envFor(dir, medium),
      stdout: () => undefined,
    });
    expect(review).toBe(1);

    const broken = await writeConfig(dir, '{');
    const incomplete = await runAuditConfig({
      env: envFor(dir, broken),
      json: true,
      stdout: () => undefined,
    });
    expect(incomplete).toBe(3);

    const missing = await runAuditConfig({
      env: {
        OPENCLAW_STATE_DIR: join(dir, 'empty'),
        OPENCLAW_CONFIG_PATH: join(dir, 'empty', 'openclaw.json'),
        HOME: dir,
        USERPROFILE: dir,
      },
      stdout: () => undefined,
    });
    expect(missing).toBe(0);
    await expect(
      runAuditConfig({
        openclawConfig: join(dir, 'missing.json'),
        env: envFor(dir, medium),
      }),
    ).rejects.toThrow(/not found/);
    await rm(dir, { recursive: true, force: true });
  });

  it('accepts CRLF config text and doctor audit as an alias', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-crlf-'));
    const configPath = await writeConfig(dir, BENIGN.replace(/\n/g, '\r\n'));
    const code = await runAuditConfig({
      env: envFor(dir, configPath),
      stdout: () => undefined,
    });
    expect(code).toBe(0);

    const lines: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    const previousHome = process.env.HOME;
    const previousProfile = process.env.USERPROFILE;
    const previousState = process.env.OPENCLAW_STATE_DIR;
    const previousConfig = process.env.OPENCLAW_CONFIG_PATH;
    process.env.HOME = dir;
    process.env.USERPROFILE = dir;
    process.env.OPENCLAW_STATE_DIR = join(dir, 'state');
    process.env.OPENCLAW_CONFIG_PATH = configPath;
    try {
      const alias = await main(['doctor', 'audit', '--json', '--no-color']);
      expect(alias).toBe(0);
      expect(lines.join('')).toContain('"command": "audit-config"');
    } finally {
      process.stdout.write = original;
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousProfile === undefined) delete process.env.USERPROFILE;
      else process.env.USERPROFILE = previousProfile;
      if (previousState === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousState;
      if (previousConfig === undefined) delete process.env.OPENCLAW_CONFIG_PATH;
      else process.env.OPENCLAW_CONFIG_PATH = previousConfig;
    }
    await rm(dir, { recursive: true, force: true });
  });

  it('flags a symlinked config without printing a private token', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-link-'));
    const configPath = await writeConfig(
      dir,
      BENIGN.replace('"${OPENCLAW_GATEWAY_TOKEN}"', `"${SECRET}"`),
    );
    const link = join(dir, 'state', 'linked.json');
    const created = await linkPath(configPath, link);
    if (!created) {
      await rm(dir, { recursive: true, force: true });
      return;
    }
    const info = await lstat(link);
    expect(info.isSymbolicLink() || process.platform === 'win32').toBe(true);
    const lines: string[] = [];
    const code = await runAuditConfig({
      json: true,
      openclawConfig: link,
      env: envFor(dir, configPath),
      stdout: (text) => lines.push(text),
    });
    const text = lines.join('');
    expect(text).not.toContain(SECRET);
    expect(text).toContain('IH-CFG-005');
    if (info.isSymbolicLink()) {
      expect(text).toContain('IH-CFG-006');
      expect(code).toBeGreaterThan(0);
    }
    await rm(dir, { recursive: true, force: true });
  });

  it('writes SARIF for config findings', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ih-cfg-sarif-'));
    const configPath = await writeConfig(
      dir,
      `{ gateway: { bind: "loopback", auth: { mode: "none" } }, tools: { exec: { security: "deny" } } }\n`,
    );
    const sarif = join(dir, 'out.sarif');
    const code = await runAuditConfig({
      env: envFor(dir, configPath),
      sarif,
      stdout: () => undefined,
    });
    expect(code).toBe(2);
    const doc = JSON.parse(await readFile(sarif, 'utf8')) as {
      version: string;
      runs: Array<{
        tool: { driver: { rules: Array<{ id: string }> } };
        results: Array<{ ruleId: string }>;
      }>;
    };
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0]?.results.some((result) => result.ruleId === 'IH-CFG-002')).toBe(true);
    expect(doc.runs[0]?.tool.driver.rules.some((rule) => rule.id === 'IH-CFG-002')).toBe(true);
    await rm(dir, { recursive: true, force: true });
  });
});
