import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { shannonEntropy } from '../src/util/entropy.ts';
import { cred006 } from '../src/rules/env-fallback.ts';
import { context, scannedFromFile, scannedText } from './support.ts';

const root = join(process.cwd(), 'test/fixtures');
const HEX = '0x0123456789abcdeffedcba9876543210aaaabbbbccccdddd1111222233334444';
const BILLING = 'sk_FAKEbillingKeyNotReal0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdXYZ';
const AIZA = 'AIzaSyFAKEWeatherKeyNotReal00000Wxyz';
const SK = 'sk-FAKEaiAnalyzerKeyNotReal0123456789abcd';
const ENTROPY = 'abcdefghijklabcdefghijkl';
const PUBLIC = '0x0123456789abcdef0123456789abcdef01234567';
const LONG_PLACEHOLDER = 'your-api-key-here-please-replace-this-now';

function hits(name: string, text: string) {
  return cred006.check(scannedText(name, text), context());
}

describe('0.16.0 IH-CRED-006 hard-coded environment fallback (aether_cell, sheeshscout)', () => {
  it('flags a multiline TypeScript private-key fallback and redacts the middle', async () => {
    const file = await scannedFromFile(join(root, 'malicious/IH-CRED-006/wallet.ts'), 'wallet.ts');
    const found = cred006.check(file, context());
    expect(found).toHaveLength(1);
    expect(found[0]?.ruleId).toBe('IH-CRED-006');
    expect(found[0]?.severity).toBe('high');
    expect(found[0]?.confidence).toBe('high');
    expect(found[0]?.line).toBe(3);
    expect(found[0]?.evidence.startsWith("process.env.PRIVATE_KEY || '0x01")).toBe(true);
    expect(found[0]?.evidence.endsWith("4444'")).toBe(true);
    expect(found[0]?.evidence).not.toContain('fedcba98');
    expect(found[0]?.evidence).not.toContain(HEX);
    expect(found[0]?.message).toContain('fallback');
    expect(found[0]?.remediation).toContain('no default');
  });

  it('flags an .mjs 0x fallback, a bracket template, and ?? ', async () => {
    const config = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/config.mjs'),
      'config.mjs',
    );
    expect(cred006.check(config, context())[0]?.evidence).toContain('WALLET_KEY');

    const bracket = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/bracket.mjs'),
      'bracket.mjs',
    );
    const slack = cred006.check(bracket, context());
    expect(slack).toHaveLength(1);
    expect(slack[0]?.evidence).toContain('xoxb');
    expect(slack[0]?.evidence).toContain('6789');
    expect(slack[0]?.evidence).not.toContain('slack-token-not-real');

    const gh = hits(
      'nullish.ts',
      "export const gh = process.env.GH_TOKEN ?? 'ghp_FAKEGitHubTokenNotReal0123456789';",
    );
    expect(gh).toHaveLength(1);
    expect(gh[0]?.evidence).toContain('ghp_');
    expect(gh[0]?.evidence).toContain('6789');
    expect(gh[0]?.evidence).not.toContain('GitHubTokenNotReal');
  });

  it('flags Python getenv, a 3-line os.environ.get, and getenv-or', async () => {
    const weather = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/weather.py'),
      'weather.py',
    );
    const google = cred006.check(weather, context());
    expect(google).toHaveLength(1);
    expect(google[0]?.evidence).toContain('AIza');
    expect(google[0]?.evidence).toContain('Wxyz');
    expect(google[0]?.evidence).not.toContain(AIZA);
    expect(google[0]?.line).toBe(5);

    const billing = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/billing.py'),
      'billing.py',
    );
    const text = await readFile(join(root, 'malicious/IH-CRED-006/billing.py'), 'utf8');
    expect(text).toContain(BILLING);
    expect(BILLING.length).toBe(67);
    const charged = cred006.check(billing, context());
    expect(charged).toHaveLength(1);
    expect(charged[0]?.line).toBe(4);
    expect(charged[0]?.confidence).toBe('high');
    expect(charged[0]?.evidence.startsWith('os.getenv("BILLING_API_KEY", "sk_F')).toBe(true);
    expect(charged[0]?.evidence.endsWith('dXYZ")')).toBe(true);
    expect(charged[0]?.evidence).not.toContain('billingKeyNotReal');
    expect(charged[0]?.evidence).not.toContain(BILLING);

    const analyzer = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/ai_analyzer.py'),
      'ai_analyzer.py',
    );
    const ai = cred006.check(analyzer, context());
    expect(ai).toHaveLength(1);
    expect(ai[0]?.evidence).toContain('getenv("OPENAI_API_KEY") or "sk-F');
    expect(ai[0]?.evidence).not.toContain(SK);
  });

  it('flags a shell ${VAR:-literal} and keeps env-to-env expansions quiet', async () => {
    const shell = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/fallback.sh'),
      'fallback.sh',
    );
    const found = cred006.check(shell, context());
    expect(found).toHaveLength(1);
    expect(found[0]?.evidence).toContain('${OPENAI_API_KEY:-sk-F');
    expect(found[0]?.evidence).not.toContain('shellFallback');

    const chain = await scannedFromFile(
      join(root, 'benign/near/IH-CRED-006/env-chain.sh'),
      'env-chain.sh',
    );
    expect(cred006.check(chain, context())).toEqual([]);
  });

  it('flags entropy-only secrets and known prefixes without a secret-like name', async () => {
    expect(shannonEntropy(ENTROPY)).toBeGreaterThanOrEqual(3.5);
    expect(shannonEntropy(ENTROPY)).toBeLessThan(4);
    expect(ENTROPY.length).toBeGreaterThanOrEqual(20);
    const password = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/entropy.py'),
      'entropy.py',
    );
    const found = cred006.check(password, context());
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe('medium');
    expect(found[0]?.evidence).toContain('abcd');
    expect(found[0]?.evidence).toContain('ijkl');
    expect(found[0]?.evidence).not.toContain('efgh');
    expect(found[0]?.evidence).not.toContain(ENTROPY);

    const region = await scannedFromFile(
      join(root, 'malicious/IH-CRED-006/region.ts'),
      'region.ts',
    );
    expect(cred006.check(region, context())).toHaveLength(1);

    const tx = await scannedFromFile(join(root, 'malicious/IH-CRED-006/tx.mjs'), 'tx.mjs');
    const txHit = cred006.check(tx, context());
    expect(txHit).toHaveLength(1);
    expect(txHit[0]?.confidence).toBe('high');
    expect(txHit[0]?.evidence).not.toContain('fedcba98');

    const aws = hits('aws.py', 'key = os.getenv("AWS_ACCESS_KEY_ID", "AKIAFAKENOTREALKEY12")\n');
    expect(aws).toHaveLength(1);
    expect(aws[0]?.evidence).toContain('AKIA');
    expect(aws[0]?.evidence).not.toContain('FAKENOTREAL');

    const pat = hits(
      'pat.js',
      "const pat = process.env.GH_PAT || 'github_pat_FAKENotARealToken0123456789abcd';\n",
    );
    expect(pat).toHaveLength(1);
    expect(pat[0]?.evidence).toContain('gith');
    expect(pat[0]?.evidence).not.toContain('NotARealToken');
  });

  it('stays quiet on placeholders, public addresses, env chains, comments, and docs', async () => {
    expect(shannonEntropy(PUBLIC)).toBeGreaterThanOrEqual(3.5);
    expect(PUBLIC.length).toBe(42);
    expect(shannonEntropy(LONG_PLACEHOLDER)).toBeGreaterThanOrEqual(3.5);
    expect(LONG_PLACEHOLDER.length).toBeGreaterThanOrEqual(20);

    for (const name of [
      'placeholders.py',
      'public-address.ts',
      'env-chain.ts',
      'docs-tx.md',
      'nonscret.ts',
      'comments.py',
      'short.js',
    ]) {
      const file = await scannedFromFile(join(root, 'benign/near/IH-CRED-006', name), name);
      expect(cred006.check(file, context()), name).toEqual([]);
    }
  });

  it('ignores markdown and other non-code files even when the text is a real fallback', () => {
    const body = `process.env.PRIVATE_KEY || '${HEX}'\n`;
    expect(hits('SKILL.md', body)).toEqual([]);
    expect(hits('notes.txt', body)).toEqual([]);
    expect(cred006.check(scannedText('readme.md', body, 'markdown'), context())).toEqual([]);
  });

  it('matches calls split across lines and a literal at the end of an env chain', () => {
    const split = [
      'key = os.getenv(',
      '    "OPENAI_API_KEY"',
      ') or "sk-FAKEaiAnalyzerKeyNotReal0123456789abcd"',
      '',
    ].join('\n');
    expect(hits('split.py', split)).toHaveLength(1);

    const jsSplit = ['const privateKey =', '  process.env.PRIVATE_KEY ||', `  '${HEX}';`, ''].join(
      '\n',
    );
    const jsHit = hits('split.ts', jsSplit);
    expect(jsHit).toHaveLength(1);
    expect(jsHit[0]?.line).toBe(3);

    const chain =
      'const key = process.env.API_KEY || process.env.BACKUP || "sk-FAKEaiAnalyzerKeyNotReal0123456789abcd";\n';
    const found = hits('chain.ts', chain);
    expect(found).toHaveLength(1);
    expect(found[0]?.evidence).toContain('BACKUP');

    const keyword =
      'os.environ.get("API_KEY", default="sk-FAKEaiAnalyzerKeyNotReal0123456789abcd")\n';
    expect(hits('keyword.py', keyword)).toHaveLength(1);

    const raw = 'os.getenv("GOOGLE_API_KEY", r"AIzaSyFAKEWeatherKeyNotReal00000Wxyz")\n';
    expect(hits('raw.py', raw)).toHaveLength(1);

    const optional = `process.env?.PRIVATE_KEY ?? '${HEX}'\n`;
    expect(hits('opt.ts', optional)).toHaveLength(1);

    const brackets = "process.env['SLACK_TOKEN'] || 'xoxb-FAKE-slack-token-not-real-0123456789'\n";
    expect(hits('brackets.ts', brackets)).toHaveLength(1);

    const camel = `const key = process.env.apiKey || "${ENTROPY}";\n`;
    expect(hits('camel.ts', camel)[0]?.confidence).toBe('medium');

    const auth = `token = os.getenv("AUTH", "${ENTROPY}")\n`;
    expect(hits('auth.py', auth)).toHaveLength(1);
    const credential = `token = os.getenv("CREDENTIAL", "${ENTROPY}")\n`;
    expect(hits('credential.py', credential)).toHaveLength(1);
    const authorization = `token = os.getenv("AUTHORIZATION", "${ENTROPY}")\n`;
    expect(hits('authorization.py', authorization)).toHaveLength(1);
  });

  it('does not treat comments, interpolation, or a non-secret name as a fallback secret', () => {
    const block = [
      '/*',
      "const t = process.env.TOKEN || 'ghp_FAKEGitHubTokenNotReal0123456789';",
      '*/',
      'const t = process.env.TOKEN;',
      '',
    ].join('\n');
    expect(hits('block.js', block)).toEqual([]);

    const interpolated = 'const key = process.env.API_KEY || `sk-${process.env.OTHER}`;\n';
    expect(hits('interp.ts', interpolated)).toEqual([]);

    const formatted = 'key = os.getenv("API_KEY", f"sk-{suffix}")\n';
    expect(hits('format.py', formatted)).toEqual([]);

    const author = `export const name = process.env.AUTHOR || "${ENTROPY}";\n`;
    expect(shannonEntropy(ENTROPY)).toBeGreaterThanOrEqual(3.5);
    expect(hits('author.ts', author)).toEqual([]);

    const same = 'const key = process.env.API_KEY || process.env.BACKUP_API_KEY;\n';
    expect(hits('same.ts', same)).toEqual([]);

    const afterString = [
      'const note = "say \\"# not a comment\\"";',
      'const tick = `plain`;',
      '// process.env.TOKEN || "sk-FAKEaiAnalyzerKeyNotReal0123456789abcd"',
      'const key = process.env.API_KEY;',
      '',
    ].join('\n');
    expect(hits('strings.ts', afterString)).toEqual([]);
  });
});
