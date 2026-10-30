import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { loadConfig } from '../../core/config.ts';
import {
  appendHistory,
  buildReport,
  readHistory,
  renderPostureHtml,
} from '../../report/posture.ts';

export interface ReportFlags {
  targets: string[];
  title?: string;
  ledger?: string;
  history?: string;
  html?: string;
  json?: boolean;
  jsonFile?: string;
  failOnBlock?: boolean;
  config?: string;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  out?: (line: string) => void;
}

export async function runReport(flags: ReportFlags): Promise<number> {
  const out = flags.out ?? ((l: string) => process.stdout.write(l + '\n'));
  const env = flags.env ?? process.env;
  const config = await loadConfig({ ...(flags.config ? { explicitPath: flags.config } : {}), env });
  const history = flags.history ? await readHistory(resolve(flags.history)) : [];
  const report = await buildReport({
    targets: flags.targets.length ? flags.targets : ['.'],
    config,
    history,
    ...(flags.title ? { title: flags.title } : {}),
    ...(flags.ledger ? { ledger: flags.ledger } : {}),
    ...(flags.now ? { now: flags.now } : {}),
  });
  if (flags.history) await appendHistory(resolve(flags.history), report);
  if (flags.html) await writeFile(resolve(flags.html), renderPostureHtml(report));
  if (flags.jsonFile)
    await writeFile(resolve(flags.jsonFile), JSON.stringify(report, null, 2) + '\n');
  if (flags.json) out(JSON.stringify(report, null, 2));
  else {
    const t = report.totals;
    out(`${report.title}: ${t.repos} repo(s), ${t.skills} skill(s), ${t.findings} finding(s)`);
    out(
      `verdicts: block ${t.verdicts.block ?? 0}, review ${t.verdicts.review ?? 0}, incomplete ${t.verdicts.incomplete ?? 0}, no findings ${t.verdicts['no-findings'] ?? 0}`,
    );
    out(
      `threat model: ${t.reposWithThreatModel}/${t.repos} repo(s), coverage ${t.threatModelCoverage === null ? 'n/a' : `${t.threatModelCoverage}%`}, ${report.violations.filter((v) => v.severity !== 'info').length} violation(s)`,
    );
    out(`drift: ${t.driftChanged} changed of ${t.driftApproved} approved`);
    const top = report.owaspLlm.filter((o) => o.findings > 0);
    if (top.length)
      out(`OWASP LLM: ${top.map((o) => `${o.id.split(':')[0]} ${o.findings}`).join(', ')}`);
    if (flags.html) out(`HTML report: ${resolve(flags.html)}`);
  }
  return flags.failOnBlock && (report.totals.verdicts.block ?? 0) > 0 ? 2 : 0;
}
