import type { Rule } from '../core/types.ts';
import { bin001 } from './binary.ts';
import { cred001, cred002, cred003 } from './credentials.ts';
import { exec001, exec002, exec003 } from './exec.ts';
import { fs001 } from './filesystem.ts';
import { inj001, inj002, inj003 } from './injection.ts';
import { integrityRules } from './integrity.ts';
import { meta001 } from './meta.ts';
import { net001, net002 } from './network.ts';
import { obf001 } from './obfuscation.ts';
import { persist001 } from './persistence.ts';
import { priv001 } from './privilege.ts';

export const contentRules: Rule[] = [
  exec001,
  exec002,
  exec003,
  net001,
  net002,
  cred001,
  cred002,
  cred003,
  inj001,
  inj002,
  inj003,
  obf001,
  persist001,
  priv001,
  bin001,
  fs001,
  meta001,
];

export function allContentRules(): Rule[] {
  return contentRules;
}

export function allRules(): Rule[] {
  return [...contentRules, ...integrityRules];
}

export function ruleById(id: string): Rule | undefined {
  return allRules().find((rule) => rule.id === id);
}
