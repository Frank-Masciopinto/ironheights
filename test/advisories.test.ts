import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readAdvisoryCache, writeAdvisoryCache } from '../src/advisories/cache.ts';
import { publicKeyHexFromSeed, signAdvisoryBytes } from '../src/advisories/crypto.ts';
import { ADVISORY_FEED_SIG_URL, ADVISORY_FEED_URL } from '../src/advisories/endpoints.ts';
import { findingsForSkill, textContainsHost, type SkillMaterial } from '../src/advisories/match.ts';
import { hexToBytes, pinnedAdvisoryPublicKey } from '../src/advisories/pinned-key.ts';
import { parseAdvisoryDocument } from '../src/advisories/schema.ts';
import { runAdvisories } from '../src/cli/commands/advisories.ts';
import { runScan } from '../src/cli/commands/scan.ts';
import { main } from '../src/cli/index.ts';
import { adv001 } from '../src/rules/advisory.ts';
import { context, scannedText } from './support.ts';

function hexLine(relative: string): Uint8Array {
  const text = readFileSync(new URL(relative, import.meta.url), 'utf8');
  const line = text
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find((item) => item.length > 0 && !item.startsWith('#'));
  if (!line) throw new Error('missing hex');
  return hexToBytes(line);
}

const testPublic = hexLine('../test/fixtures/advisories/test-public.hex');
const testSeed = hexLine('../test/fixtures/advisories/test-private.hex');

function feed(advisories: unknown[]): { json: string; sig: string } {
  const document = {
    schemaVersion: 1,
    generatedAt: '2026-10-10T00:00:00.000Z',
    advisories,
  };
  const json = `${JSON.stringify(document, null, 2)}\n`;
  return { json, sig: signAdvisoryBytes(new TextEncoder().encode(json), testSeed) };
}

const sample = {
  id: 'IH-2026-0001',
  skill: 'notes',
  owner: 'ada',
  versions: ['1.0.0'],
  contentHashes: [] as string[],
  campaign: 'demo-campaign',
  iocHosts: ['evil.example'],
  sources: ['https://ironheights.dev/tracker/demo-campaign'],
  firstSeen: '2026-10-01',
  status: 'malicious',
};

describe('advisory feed', () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it('pins the production advisory key and still verifies with the injected test key', () => {
    const production = '8424b837422792656e6e7500869395a5afe64bf163baa63acea83f1e97cc2b6c';
    const pinned = pinnedAdvisoryPublicKey();
    expect(Buffer.from(pinned ?? new Uint8Array()).toString('hex')).toBe(production);
    expect(Buffer.from(testPublic).toString('hex')).not.toBe(production);
    expect(publicKeyHexFromSeed(testSeed)).toBe(Buffer.from(testPublic).toString('hex'));
    const signed = feed([sample]);
    expect(parseAdvisoryDocument(signed.json).advisories).toHaveLength(1);
    const material: SkillMaterial = {
      skillName: 'notes',
      dirName: 'notes',
      version: '1.0.0',
      files: [
        { relativePath: 'SKILL.md', sha256: 'ab'.repeat(32), text: 'see https://evil.example/a' },
      ],
    };
    const hits = findingsForSkill(material, parseAdvisoryDocument(signed.json), 'ada', 'critical');
    expect(hits.map((item) => item.ruleId)).toEqual(['IH-ADV-001']);
    expect(hits[0]?.remediation).toContain('https://ironheights.dev/tracker/demo-campaign');
    expect(textContainsHost('prefix notevil.example suffix', 'evil.example')).toBe(false);
    expect(textContainsHost('https://evil.example.com/a', 'evil.example')).toBe(false);
    expect(adv001.check(scannedText('SKILL.md', 'IH-ADV-001'), context())).toEqual([]);
  });

  it('matches a hash when the version does not, and skips a version-specific name', () => {
    const hash = 'c'.repeat(64);
    const signed = feed([{ ...sample, versions: ['9.9.9'], contentHashes: [`sha256:${hash}`] }]);
    const document = parseAdvisoryDocument(signed.json);
    const named: SkillMaterial = {
      skillName: 'notes',
      dirName: 'notes',
      version: '1.0.0',
      files: [{ relativePath: 'SKILL.md', sha256: 'a'.repeat(64), text: 'clean' }],
    };
    expect(findingsForSkill(named, document, 'ada', 'critical')).toEqual([]);
    const hashed: SkillMaterial = {
      ...named,
      files: [{ relativePath: 'SKILL.md', sha256: hash, text: 'clean' }],
    };
    expect(findingsForSkill(hashed, document, 'other', 'critical')).toHaveLength(1);
    const otherOwner: SkillMaterial = named;
    const nameOnly = feed([{ ...sample, contentHashes: [], iocHosts: [] }]);
    expect(
      findingsForSkill(otherOwner, parseAdvisoryDocument(nameOnly.json), 'bob', 'critical'),
    ).toEqual([]);
  });

  it('updates from the pinned URLs and does not replace a good cache when the signature is bad', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-adv-'));
    dirs.push(root);
    const signed = feed([sample]);
    const calls: string[] = [];
    const lines: string[] = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      if (init?.redirect !== 'manual') throw new Error('redirect was not manual');
      const url = String(input);
      calls.push(url);
      expect(lines.join('')).toContain(url);
      if (url === ADVISORY_FEED_URL) return new Response(signed.json);
      if (url === ADVISORY_FEED_SIG_URL) return new Response(signed.sig);
      return new Response('no', { status: 404 });
    };
    const code = await runAdvisories('update', {
      env: { IRONHEIGHTS_HOME: root },
      stdout: (text) => lines.push(text),
      fetchImpl,
      publicKey: testPublic,
    });
    expect(code).toBe(0);
    expect(calls).toEqual([ADVISORY_FEED_URL, ADVISORY_FEED_SIG_URL]);
    expect(lines.join('')).toContain('signature verified');
    const shown: string[] = [];
    expect(
      await runAdvisories('show', {
        env: { IRONHEIGHTS_HOME: root },
        stdout: (text) => shown.push(text),
        publicKey: testPublic,
      }),
    ).toBe(0);
    expect(shown.join('')).toContain('IH-2026-0001');

    const badFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url === ADVISORY_FEED_URL) return new Response(signed.json);
      return new Response('ed25519 aaaa\n');
    };
    await expect(
      runAdvisories('update', {
        env: { IRONHEIGHTS_HOME: root },
        stdout: () => undefined,
        fetchImpl: badFetch,
        publicKey: testPublic,
      }),
    ).rejects.toThrow(/signature is invalid/);
    const still = await readAdvisoryCache(root, testPublic);
    expect(still.status).toBe('ok');
  });

  it('fails closed when the key is absent, the production key does not match, or the cache was tampered', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-adv-bad-'));
    dirs.push(root);
    const signed = feed([sample]);
    await writeAdvisoryCache(root, signed.json, signed.sig);
    const wrongKey = await readAdvisoryCache(root, pinnedAdvisoryPublicKey());
    expect(wrongKey.status).toBe('rejected');
    const missing = await readAdvisoryCache(join(root, 'empty'), null);
    expect(missing.status).toBe('missing');
    const rejected = await readAdvisoryCache(root, null);
    expect(rejected.status).toBe('rejected');
    await writeFile(join(root, 'advisories.json.sig'), 'ed25519 aaaa\n');
    const tampered = await readAdvisoryCache(root, testPublic);
    expect(tampered.status).toBe('rejected');
  });

  it('reports IH-ADV-001 during scan when the cache matches', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-adv-scan-'));
    dirs.push(root);
    const skill = join(root, 'notes');
    await mkdir(skill);
    await writeFile(
      join(skill, 'SKILL.md'),
      '---\nname: notes\ndescription: Local notes.\nversion: 1.0.0\n---\n\nhello\n',
    );
    const signed = feed([{ ...sample, versions: ['*'], iocHosts: [], contentHashes: [] }]);
    await writeAdvisoryCache(join(root, 'ih'), signed.json, signed.sig);
    const lines: string[] = [];
    const code = await runScan({
      paths: [skill],
      noColor: true,
      env: { IRONHEIGHTS_HOME: join(root, 'ih'), OPENCLAW_STATE_DIR: join(root, 'state') },
      stdout: (text) => lines.push(text),
      advisoryPublicKey: testPublic,
      skillOwner: 'ada',
    });
    expect(code).toBe(2);
    expect(lines.join('')).toContain('IH-ADV-001');
    expect(lines.join('')).toContain('https://ironheights.dev/tracker/demo-campaign');
    expect(lines.join('')).toContain('Advisory feed: 1 entries');
  });

  it('signs a feed with the tooling script', async () => {
    const root = await mkdtemp(join(tmpdir(), 'ih-sign-'));
    dirs.push(root);
    const source = join(root, 'source.json');
    await writeFile(
      source,
      JSON.stringify({
        generatedAt: '2026-10-10T00:00:00.000Z',
        advisories: [{ ...sample, contentHashes: ['sha256:' + 'ab'.repeat(32)] }],
      }),
    );
    const out = join(root, 'advisories.json');
    const result = spawnSync(
      process.execPath,
      [
        'scripts/sign-advisories.mjs',
        '--source',
        source,
        '--key',
        'test/fixtures/advisories/test-private.hex',
        '--out',
        out,
      ],
      { encoding: 'utf8' },
    );
    expect(result.status).toBe(0);
    const json = await readFile(out);
    const sig = await readFile(`${out}.sig`, 'utf8');
    const cache = join(root, 'cache');
    await writeAdvisoryCache(cache, json.toString('utf8'), sig);
    const read = await readAdvisoryCache(cache, testPublic);
    expect(read.status).toBe('ok');
    if (read.status === 'ok')
      expect(read.document.advisories[0]?.contentHashes[0]).toBe('ab'.repeat(32));
  });

  it('treats --online as an explicit feed refresh and then continues', async () => {
    const lines: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url === ADVISORY_FEED_URL) return new Response('{}');
      return new Response('ed25519 aaaa\n');
    };
    try {
      const code = await main(['--online', 'scan', 'test/fixtures/benign'], { fetchImpl });
      expect(code).toBe(70);
      expect(lines.join('')).toContain(ADVISORY_FEED_URL);
      expect(lines.join('')).toContain(ADVISORY_FEED_SIG_URL);
    } finally {
      process.stdout.write = original;
    }
  });
});
