import { createHash } from 'node:crypto';
import { mkdtemp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { callTool } from '../src/mcp/server.ts';
import { clawhubFileUrl, clawhubSkillUrl, clawhubVersionUrl } from '../src/net/clawhub.ts';

function routes(owner: string, slug: string, version: string): Map<string, Uint8Array> {
  const enc = new TextEncoder();
  const bytes = enc.encode(`---\nname: ${slug}\ndescription: Notes.\n---\n\nSay hi.\n`);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  return new Map([
    [
      clawhubSkillUrl(slug, owner),
      enc.encode(
        JSON.stringify({ skill: { slug }, latestVersion: { version }, owner: { handle: owner } }),
      ),
    ],
    [
      clawhubVersionUrl(slug, version, owner),
      enc.encode(
        JSON.stringify({
          version: { version, files: [{ path: 'SKILL.md', size: bytes.byteLength, sha256 }] },
        }),
      ),
    ],
    [clawhubFileUrl(slug, version, owner, 'SKILL.md'), bytes],
  ]);
}

describe('mcp regressions', () => {
  it('check_skill errors on a path that does not exist instead of a clean verdict', async () => {
    const home = await mkdtemp(join(tmpdir(), 'ih-mcp-home-'));
    const r = await callTool(
      'check_skill',
      { path: join(home, 'missing') },
      { env: { ...process.env, IRONHEIGHTS_HOME: home } },
    );
    expect(r.isError).toBe(true);
    expect((r.structuredContent as { error: string }).error).toMatch(/not a directory/);
  });

  it('check_skill removes the whole ironheights-fetch-* staging folder', async () => {
    const tmp = await mkdtemp(join(tmpdir(), 'ih-mcp-tmp-'));
    const old = process.env.TMPDIR;
    process.env.TMPDIR = tmp;
    try {
      const map = routes('ada', 'notes', '1.0.0');
      const fetchImpl: typeof fetch = async (input) => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        const body = map.get(url);
        return body ? new Response(body) : new Response('missing', { status: 404 });
      };
      const r = await callTool(
        'check_skill',
        { skill: 'ada/notes@1.0.0' },
        { env: { ...process.env, IRONHEIGHTS_HOME: tmp }, fetchImpl },
      );
      expect(r.isError).toBeFalsy();
      expect((r.structuredContent as { verdict: string }).verdict).toBe('no-findings');
      expect((await readdir(tmp)).filter((n) => n.startsWith('ironheights-fetch-'))).toEqual([]);
    } finally {
      if (old === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = old;
    }
  });
});
