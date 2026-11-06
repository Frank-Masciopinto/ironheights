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
import { intent001 } from './intent.ts';
import { intent002 } from './purpose-reach.ts';
import { flow001 } from './dataflow.ts';
import { integrityRules } from './integrity.ts';
import { llm001 } from './llm.ts';
import { mcp001, mcp002, mcp003 } from './mcp.ts';
import { meta001 } from './meta.ts';
import { ref001 } from './missing-file.ts';
import { ref002 } from './text-exfil.ts';
import { exec006 } from './conditional-trailer.ts';
import { inj005, inj006, ref003 } from './hidden-instructions.ts';
import { inj007 } from './session-instructions.ts';
import { expBatchRules } from './exp-batch.ts';
import { exp1106Rules } from './exp-1106.ts';
import { exp1116Rules } from './exp-1116.ts';
import { meta005 } from './rebuildable.ts';
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
  intent001,
  intent002,
  flow001,
  obf001,
  persist001,
  priv001,
  bin001,
  bin002,
  fs001,
  meta001,
  ref001,
  ref002,
  exec006,
  inj005,
  inj006,
  ref003,
  inj007,
  ...expBatchRules,
  ...exp1106Rules,
  ...exp1116Rules,
  meta005,
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
