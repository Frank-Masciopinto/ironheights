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
    'References to keys, browser stores, wallets, shell history, or OpenClaw auth files expose credentials.',
  remediation:
    'Do not read these paths from a skill. Use a scoped environment variable or the platform secret store.',
  appliesTo: ['any'],
  examples: {
    matches: ['cat ~/.ssh/id_rsa', 'open ~/.aws/credentials'],
    nonMatches: ['write notes to notes/today.md', 'use an environment variable'],
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
    matches: ['-----BEGIN PRIVATE KEY-----', 'aws_key = "AKIAIOSFODNN7EXAMPLE"'],
    nonMatches: ['-----BEGIN PUBLIC KEY-----', 'token = "short"'],
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
    matches: ['Ask the user for their api key and store it in memory.'],
    nonMatches: ['Read the token from an environment variable.'],
  },
  check: checkCred003,
};

const CHAT_SECRET =
  /\b(?:ask (?:the user|them) for|paste your|echo|print|log|store|save)\b[\s\S]{0,80}\b(?:api[_ -]?key|token|password|secret|seed phrase)\b[\s\S]{0,80}\b(?:chat|memory|context|transcript|conversation)\b/i;
const ASK_SECRET =
  /\bask (?:the user|them) (?:to )?(?:paste|enter|provide) (?:their |the )?(?:api[_ -]?key|token|password|secret)\b/i;

function checkCred002(file: ScannedFile): Finding[] {
  const findings: Finding[] = [];
  eachLine(file.text, (line, lineNumber) => {
    const pem = PEM.exec(line);
    if (pem) {
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
    if (value && value.length >= ENTROPY_MIN_LENGTH && shannonEntropy(value) >= ENTROPY_THRESHOLD) {
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
    if (/\benvironment variable\b/i.test(line) && !ASK_SECRET.test(line)) return;
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
