import { cp, mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runReport } from '../src/cli/commands/report.ts';
import { renderPostureHtml, resolveRepos, type PostureReport } from '../src/report/posture.ts';

async function org() {
  const dir = await mkdtemp(join(tmpdir(), 'ih-org-'));
  await cp('examples/threatmodel', join(dir, 'repo-a'), { recursive: true });
  await mkdir(join(dir, 'repo-b', 'skills'), { recursive: true });
  await cp('test/fixtures/malicious/IH-CRED-001', join(dir, 'repo-b', 'skills', 'cred'), {
    recursive: true,
  });
  return dir;
}

describe('posture report', () => {
  it('expands an org folder into repositories', async () => {
    const dir = await org();
    expect((await resolveRepos([dir])).map((r) => r.slice(dir.length + 1))).toEqual([
      'repo-a',
      'repo-b',
    ]);
  });

  it('builds inventory, OWASP mapping, coverage, HTML and a trend', async () => {
    const dir = await org();
    const hist = join(dir, 'hist.jsonl');
    const html = join(dir, 'r.html');
    const lines: string[] = [];
    const now = new Date('2026-10-30T12:00:00Z');
    await runReport({ targets: [dir], history: hist, now, out: () => undefined });
    expect(
      await runReport({
        targets: [dir],
        history: hist,
        html,
        json: true,
        failOnBlock: true,
        now,
        out: (l) => lines.push(l),
      }),
    ).toBe(2);
    const r = JSON.parse(lines.join('\n')) as PostureReport;
    expect(r.totals.repos).toBe(2);
    expect(r.totals.skills).toBe(2);
    expect(r.totals.verdicts.block).toBe(1);
    expect(r.totals.reposWithThreatModel).toBe(1);
    expect(r.totals.threatModelCoverage).toBe(50);
    expect(r.owaspLlm).toHaveLength(10);
    expect(r.owaspLlm.find((o) => o.id === 'LLM02:2025')?.findings).toBeGreaterThan(0);
    expect(r.history).toHaveLength(2);
    const page = await readFile(html, 'utf8');
    expect(page).toContain('OWASP Top 10 for LLM Applications 2025');
    expect(page).toContain('<h2>Trend</h2>');
    expect(page).toContain('protects any AI bot that installs it');
  });

  it('escapes untrusted names in HTML', () => {
    const page = renderPostureHtml({
      tool: 'ironheights',
      version: '0',
      title: '<script>x</script>',
      generatedAt: 'now',
      totals: {
        repos: 0,
        skills: 0,
        grades: {},
        verdicts: {},
        findings: 0,
        reposWithThreatModel: 0,
        threatModelCoverage: null,
        driftChanged: 0,
        driftApproved: 0,
        coverage: { inspected: 0, loaded: 0, complete: true },
        overall: 'nothing-scanned',
        result: 'nothing scanned: 0 skills found',
      },
      fingerprint: 'f'.repeat(64),
      validUntil: '2026-11-07T00:00:00.000Z',
      owaspLlm: [],
      repos: [],
      skills: [],
      violations: [],
      driftChanges: [],
      history: [],
    });
    expect(page).not.toContain('<script>x');
    expect(page).toContain('&lt;script&gt;');
  });

  it('reports no phantom skill for an empty folder or an empty skills/ dir', async () => {
    for (const make of [[], ['skills']]) {
      const dir = await mkdtemp(join(tmpdir(), 'ih-empty-'));
      if (make.length) await mkdir(join(dir, ...make), { recursive: true });
      const lines: string[] = [];
      expect(await runReport({ targets: [dir], json: true, out: (l) => lines.push(l) })).toBe(0);
      const r = JSON.parse(lines.join('\n')) as PostureReport;
      expect(r.skills).toEqual([]);
      expect(r.totals.skills).toBe(0);
    }
  });

  it('fails with exit 1 on a target that does not exist', async () => {
    const errs: string[] = [];
    const code = await runReport({
      targets: [join(tmpdir(), 'ih-does-not-exist-' + Date.now())],
      out: () => undefined,
      err: (l) => errs.push(l),
    });
    expect(code).toBe(1);
    expect(errs.join('')).toMatch(/not a directory/);
  });
});
