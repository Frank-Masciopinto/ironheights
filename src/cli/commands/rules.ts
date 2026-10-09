import { UsageError } from '../../core/errors.ts';
import { allRules, ruleById } from '../../rules/index.ts';

export function runRules(
  action: string | undefined,
  id: string | undefined,
  stdout: (text: string) => void = (text) => process.stdout.write(text),
): number {
  if (action === 'list') {
    for (const rule of allRules()) {
      stdout(`${rule.id}\t${rule.severity}\t${rule.priority}\t${rule.title}\n`);
    }
    return 0;
  }
  if (action === 'show') {
    if (!id) throw new UsageError('rules show requires an id');
    const rule = ruleById(id);
    if (!rule) throw new UsageError(`unknown rule ${id}`);
    stdout(`${rule.id} ${rule.title}\n${rule.description}\nRemediation: ${rule.remediation}\n`);
    return 0;
  }
  throw new UsageError('rules requires list or show');
}
