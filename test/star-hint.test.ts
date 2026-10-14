import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { CLAWHUB_URL, runScan, type ScanFlags } from '../src/cli/commands/scan.ts';

const BENIGN = join(process.cwd(), 'test/fixtures/benign');
const MALICIOUS = join(process.cwd(), 'test/fixtures/malicious/IH-EXEC-001');

describe('star hint after a clean scan', () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  async function scan(extra: Partial<ScanFlags> & { env?: NodeJS.ProcessEnv } = {}) {
    const home = await mkdtemp(join(tmpdir(), 'ih-star-'));
    dirs.push(home);
    const out: string[] = [];
    const err: string[] = [];
    const code = await runScan({
      paths: [BENIGN],
      noColor: true,
      isTTY: true,
      ...extra,
      env: { IRONHEIGHTS_HOME: home, ...extra.env },
      stdout: (t) => out.push(t),
      stderr: (t) => err.push(t),
    });
    return { code, out: out.join(''), err: err.join('') };
  }

  it('prints one line to stderr after a clean scan in a terminal', async () => {
    const { code, out, err } = await scan();
    expect(code).toBe(0);
    expect(out).not.toContain(CLAWHUB_URL);
    const lines = err.split('\n').filter((l) => l.includes(CLAWHUB_URL));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('IRONHEIGHTS_NO_STAR_HINT=1');
  });

  it.each([
    ['not a TTY', { isTTY: false }],
    ['--quiet', { quiet: true }],
    ['--json', { json: true }],
    ['--format html', { format: 'html' }],
    ['CI=true', { env: { CI: 'true' } }],
    ['IRONHEIGHTS_NO_STAR_HINT=1', { env: { IRONHEIGHTS_NO_STAR_HINT: '1' } }],
  ] as const)('stays silent when %s', async (_name, extra) => {
    const { err, out } = await scan(extra as Partial<ScanFlags>);
    expect(err + out).not.toContain(CLAWHUB_URL);
  });

  it('still shows with CI=false or IRONHEIGHTS_NO_STAR_HINT=0', async () => {
    const { err } = await scan({ env: { CI: 'false', IRONHEIGHTS_NO_STAR_HINT: '0' } });
    expect(err).toContain(CLAWHUB_URL);
  });

  it('never shows when the scan has findings', async () => {
    const { code, err, out } = await scan({ paths: [MALICIOUS] });
    expect(code).not.toBe(0);
    expect(err + out).not.toContain(CLAWHUB_URL);
  });
});
