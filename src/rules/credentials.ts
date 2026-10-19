import type { Finding, Rule, ScannedFile } from '../core/types.ts';
import { ENTROPY_MIN_LENGTH, ENTROPY_THRESHOLD, shannonEntropy } from '../util/entropy.ts';
import { maskSecret, maskWithin } from '../util/mask.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';
import { hasSensitiveMarker } from './network.ts';

/**
 * IH-CRED-002 entropy: a quoted value of at least 20 characters assigned to a
 * key-like name is flagged when its Shannon entropy is at least 4 bits/char.
 * Evidence always keeps only the first four characters of the secret.
 */

const PEM = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/;
/** Base64 key material: a PEM body line, or the same text after a literal \\n escape. */
const PEM_BODY_LINE = /^\s*["'`]?\s*[A-Za-z0-9+/]{40,}={0,2}\s*(?:\\n)?["'`,]*\s*$/;
const PEM_BODY_INLINE = /PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/]{40,}/;
/** A public EVM address (0x + 40 hex) is not a secret; a 0x + 64 hex private key still is. */
const PUBLIC_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
/** 0x + 64 hex assigned to a secret-like name: an EVM private key (hex entropy stays under 4 bits). */
const HEX_PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const AWS = /\b(AKIA[0-9A-Z]{16})\b/;
const GITHUB = /\b(ghp_[A-Za-z0-9]{20,80}|github_pat_[A-Za-z0-9_]{20,80}|gho_[A-Za-z0-9]{20,80})\b/;
const SLACK = /\b(xox[baprs]-[A-Za-z0-9-]{10,80})\b/;
const ASSIGN =
  /\b((?:api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key))\b\s*[:=]\s*['"]([A-Za-z0-9+/=_-]{20,200})['"]/i;

export const cred001: Rule = {
  id: 'IH-CRED-001',
  title: 'Access to a sensitive path',
  category: 'credentials',
  severity: 'high',
  priority: 'P0',
  description:
    'References to keys, browser stores, wallets, shell history, or OpenClaw auth files expose credentials. A credential directory such as ~/.ssh, ~/.aws, ~/.gnupg, or ~/.azure counts with or without a file name after it. Windows forms count too: ~\\.ssh, %USERPROFILE%\\.ssh, and AppData paths for Chrome, Firefox, or the credential store.',
  remediation:
    'Do not read these paths from a skill. Use a scoped environment variable or the platform secret store.',
  appliesTo: ['any'],
  examples: {
    matches: [
      'cat ~/.ssh/id_rsa',
      'open ~/.aws/credentials',
      '~/.ssh',
      '~/.gnupg/',
      'type %USERPROFILE%\\.ssh\\id_rsa',
      'Get-Content ~\\.aws\\credentials',
      '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data',
    ],
    nonMatches: [
      'write notes to notes/today.md',
      'use an environment variable',
      'const token = process.env.API_TOKEN',
      'the browser stores cookies for the site',
      'Never upload `.env` or tokens.',
      'the sshd service accepts local connections',
      'Use %USERPROFILE% as the home directory for notes.',
      'AppData stores application settings for the editor.',
    ],
  },
  check(file) {
    const findings: Finding[] = [];
    if (!hasSensitiveMarker(file.text)) return findings;
    eachLine(file.text, (line, lineNumber) => {
      if (!hasSensitiveMarker(line)) return;
      pushUnique(
        findings,
        createFinding(cred001, file, {
          line: lineNumber,
          evidence: line,
          message: 'The file references a sensitive credential or secret path.',
          confidence: 'high',
        }),
      );
    });
    return findings;
  },
};

export const cred002: Rule = {
  id: 'IH-CRED-002',
  title: 'Hard-coded secret',
  category: 'credentials',
  severity: 'high',
  priority: 'P0',
  description:
    'Private keys and live tokens checked into a skill can be copied by anyone who reads the skill.',
  remediation: 'Remove the secret, rotate it, and load it from the environment or a secret store.',
  appliesTo: ['any'],
  examples: {
    matches: [
      '-----BEGIN PRIVATE KEY-----',
      '-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7',
      'aws_key = "AKIAIOSFODNN7EXAMPLE"',
    ],
    nonMatches: [
      '-----BEGIN PUBLIC KEY-----',
      'token = "short"',
      'The file starts with -----BEGIN PRIVATE KEY----- and ends with the END line.',
      'token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"',
    ],
  },
  check: checkCred002,
};

export const cred003: Rule = {
  id: 'IH-CRED-003',
  title: 'Secret asked for in chat or memory',
  category: 'credentials',
  severity: 'medium',
  priority: 'P1',
  description: 'Asking the user to paste a secret into chat or memory stores it in the transcript.',
  remediation:
    'Tell the user to set an environment variable or use the secret store, and do not echo the value.',
  appliesTo: ['markdown', 'any'],
  examples: {
    matches: [
      'Ask the user for their api key and store it in memory.',
      'Store API key in TOOLS.md:',
    ],
    nonMatches: [
      'Read the token from an environment variable.',
      'Store tokens in an env var or secret store, never a source file; if one lands in a chat, tell the human.',
      'Never save the API key to MEMORY.md.',
    ],
  },
  check: checkCred003,
};

const CHAT_SECRET =
  /\b(?:ask (?:the user|them) for|paste your|echo|print|log|store|save)\b[\s\S]{0,80}\b(?:api[_ -]?key|token|password|secret|seed phrase)\b[\s\S]{0,80}\b(?:chat|memory|context|transcript|conversation|TOOLS\.md|MEMORY\.md)(?![\w-])/i;
/** "Store tokens in an env var or secret store" is the advice we want, not a leak (openspender). */
const SECRET_WORD = /\b(?:api[_ -]?key|token|password|secret|seed phrase|credentials?)\b/i;
const SAFE_STORE =
  /\b(?:store|keep|save|put|set)\b[^.\n]{0,40}\b(?:in|to|as)\s+(?:an?\s+|the\s+|your\s+)?(?:env(?:ironment)?\s+var(?:iable)?s?|secret\s+(?:store|manager)|keychain|keyring|vault)\b/i;
const NEGATED_STORE =
  /\b(?:never|do not|don't|dont|not)\b[^.\n]{0,30}\b(?:paste|save|store|put|write|log|print|echo|share)\b/i;
const ASK_SECRET =
  /\bask (?:the user|them) (?:to )?(?:paste|enter|provide) (?:their |the )?(?:api[_ -]?key|token|password|secret)\b/i;

const PEM_PLACEHOLDER =
  /^\s*["'`]?\s*(?:\.{2,}|\u2026|<[^>]*>|\[[^\]]*\]|your[\w -]*|paste\b|\(.*\)|#|-----END\b)/i;
const PEM_STANDALONE_PREFIX = /^\s*(?:(?:export\s+)?[\w.-]+\s*[:=]\s*)?["'`]?\s*$/;
const PEM_STANDALONE_SUFFIX = /^\s*(?:\\n)?\s*["'`,]*\s*$/;

/**
 * A private-key header counts when key material follows it, inline or on the next
 * line, or when it stands alone on its line and is not followed by a placeholder.
 * A header quoted in prose ("should start with -----BEGIN PRIVATE KEY-----") or
 * followed by "..." or "your-private-key-here" is documentation, not a key.
 */
function isRealPem(lines: readonly string[], index: number, header: RegExpExecArray): boolean {
  const line = lines[index] ?? '';
  if (PEM_BODY_INLINE.test(line)) return true;
  const prefix = line.slice(0, header.index);
  const suffix = line.slice(header.index + header[0].length);
  if (/^\s*\\n/.test(suffix)) {
    const rest = suffix.replace(/^\s*\\n/, '');
    if (PEM_PLACEHOLDER.test(rest) || rest.trim() === '' || /^["'`,]/.test(rest.trim()))
      return false;
  }
  if (!PEM_STANDALONE_PREFIX.test(prefix) || !PEM_STANDALONE_SUFFIX.test(suffix)) return false;
  for (let j = index + 1; j < Math.min(lines.length, index + 3); j += 1) {
    const next = lines[j] ?? '';
    if (next.trim() === '') continue;
    if (PEM_BODY_LINE.test(next)) return true;
    return !PEM_PLACEHOLDER.test(next);
  }
  return true;
}

function checkCred002(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const allLines = file.text.split(/\r?\n/);
  eachLine(file.text, (line, lineNumber) => {
    const pem = PEM.exec(line);
    if (pem && isRealPem(allLines, lineNumber - 1, pem)) {
      pushUnique(
        findings,
        createFinding(cred002, file, {
          line: lineNumber,
          evidence: maskSecret(pem[0] ?? 'PRIVATE KEY'),
          severity: 'critical',
          message: 'A private key header is hard-coded in the file.',
          confidence: 'high',
        }),
      );
    }
    for (const pattern of [AWS, GITHUB, SLACK]) {
      const match = pattern.exec(line);
      const secret = match?.[1];
      if (!secret) continue;
      pushUnique(
        findings,
        createFinding(cred002, file, {
          line: lineNumber,
          evidence: maskWithin(line, secret),
          severity:
            secret.startsWith('AKIA') ||
            secret.startsWith('ghp_') ||
            secret.startsWith('github_pat_') ||
            secret.startsWith('xox')
              ? 'high'
              : 'high',
          message: 'A known token or access-key prefix is hard-coded in the file.',
          confidence: 'high',
        }),
      );
    }
    const assigned = ASSIGN.exec(line);
    const value = assigned?.[2];
    if (
      value &&
      !PUBLIC_ADDRESS.test(value) &&
      (HEX_PRIVATE_KEY.test(value) ||
        (value.length >= ENTROPY_MIN_LENGTH && shannonEntropy(value) >= ENTROPY_THRESHOLD))
    ) {
      pushUnique(
        findings,
        createFinding(cred002, file, {
          line: lineNumber,
          evidence: maskWithin(line, value),
          message: 'A high-entropy value is assigned to a secret-like name.',
          confidence: 'medium',
        }),
      );
    }
  });
  return findings;
}

function checkCred003(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  const text = file.text;
  if (!CHAT_SECRET.test(text) && !ASK_SECRET.test(text)) return findings;
  eachLine(text, (line, lineNumber) => {
    const window = text
      .split(/\r?\n/)
      .slice(lineNumber - 1, lineNumber + 2)
      .join(' ');
    if (!CHAT_SECRET.test(window) && !ASK_SECRET.test(line)) return;
    // Report the line that names the secret, not the two lines above it.
    if (!ASK_SECRET.test(line) && !SECRET_WORD.test(line)) return;
    if (/\benvironment variable\b/i.test(line) && !ASK_SECRET.test(line)) return;
    if (!ASK_SECRET.test(line) && (SAFE_STORE.test(line) || NEGATED_STORE.test(line))) return;
    if (!ASK_SECRET.test(line) && !CHAT_SECRET.test(line) && SAFE_STORE.test(window)) return;
    pushUnique(
      findings,
      createFinding(cred003, file, {
        line: lineNumber,
        evidence: line,
        message: 'The skill asks to reveal or store a secret in chat, memory, or model context.',
        confidence: 'medium',
      }),
    );
  });
  return findings;
}
