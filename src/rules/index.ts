import { configRules } from '../audit/rules.ts';
import type { Rule } from '../core/types.ts';
import { advisoryRules } from './advisory.ts';
import { cred004, cred005, exec004 } from './accuracy.ts';
import { bin001 } from './binary.ts';
import { dep001 } from './dependency.ts';
import { cred001, cred002, cred003 } from './credentials.ts';
import { cred006 } from './env-fallback.ts';
import { exec005 } from './ambient-env.ts';
import { exec001, exec002, exec003 } from './exec.ts';
import { fs001 } from './filesystem.ts';
import { inj001, inj002, inj003 } from './injection.ts';
import { integrityRules } from './integrity.ts';
import { llm001 } from './llm.ts';
import { mcp001, mcp002, mcp003 } from './mcp.ts';
import { meta001 } from './meta.ts';
import { ref001 } from './missing-file.ts';
import { net001, net002 } from './network.ts';
import { obf001 } from './obfuscation.ts';
import { persist001 } from './persistence.ts';
import { priv001 } from './privilege.ts';
import { bin002, inj004 } from './remote.ts';

export const contentRules: Rule[] = [
  exec001,
  exec002,
  exec003,
  exec004,
  exec005,
  net001,
  net002,
  cred001,
  cred002,
  cred003,
  cred004,
  cred005,
  cred006,
  inj001,
  inj002,
  inj003,
  inj004,
  obf001,
  persist001,
  priv001,
  bin001,
  bin002,
  fs001,
  meta001,
  ref001,
  mcp001,
  mcp002,
  mcp003,
];

export function allContentRules(): Rule[] {
  return contentRules;
}

export function allRules(): Rule[] {
  return [...contentRules, ...integrityRules, ...advisoryRules, ...configRules, dep001, llm001];
}

export function ruleById(id: string): Rule | undefined {
  return allRules().find((rule) => rule.id === id);
}
