import type { Finding, Rule } from '../core/types.ts';
import { eachLine } from '../util/text.ts';
import { createFinding, pushUnique } from './helpers.ts';

/** Long hex runs, runtime base64 decode of a blob, packed code, split keywords, and char-code construction. */

const HEX_BLOB = /(?:\\x[0-9a-fA-F]{2}){12,}/;
const BASE64_DECODE = /\b(?:atob|base64\.b64decode|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/]{80,}/;
const PACKED = /\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/;
const SPLIT_WORD = /['"](?:ev|ex|cu|ba|sh)['"]\s*\+\s*['"](?:al|ec|rl|sh)['"]/i;
const FROM_CHAR = /\b(?:String\.fromCharCode|chr)\s*\(/;

export const obf001: Rule = {
  id: 'IH-OBF-001',
  title: 'Obfuscated code',
  category: 'obfuscation',
  severity: 'medium',
  priority: 'P1',
  description:
    'Packed or encoded payloads are used to hide a command from a person reviewing the skill.',
  remediation:
    'Ship readable source. Reject skills that decode or reconstruct commands at runtime.',
  appliesTo: ['script', 'markdown', 'any'],
  examples: {
    matches: ['eval(function(p,a,c,k,e,d){})', "atob('aaaaaaaa...')"],
    nonMatches: ['const label = "evaluation";'],
  },
  check(file) {
    const findings: Finding[] = [];
    eachLine(file.text, (line, lineNumber) => {
      if (
        HEX_BLOB.test(line) ||
        BASE64_DECODE.test(line) ||
        PACKED.test(line) ||
        SPLIT_WORD.test(line) ||
        FROM_CHAR.test(line)
      ) {
        pushUnique(
          findings,
          createFinding(obf001, file, {
            line: lineNumber,
            evidence: line.slice(0, 120),
            message: 'The file contains obfuscated or reconstructed code.',
            confidence: 'medium',
          }),
        );
      }
    });
    return findings;
  },
};
