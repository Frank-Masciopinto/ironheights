// Reads the scanner JSON written by action.yml and turns it into step outputs,
// an optional shields.io endpoint badge file and an optional job summary.
// Local only: no network, no secrets.
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

const COLORS = { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', E: 'red', F: 'red' };

export function summarize(result) {
  const skills = Array.isArray(result?.skills) ? result.skills : [];
  const findings = skills.flatMap((s) => (Array.isArray(s.findings) ? s.findings : []));
  return {
    grade: result?.grade?.letter ?? '',
    score: typeof result?.grade?.score === 'number' ? result.grade.score : '',
    verdict: result?.verdict ?? '',
    findings,
    skills,
    version: result?.tool?.version ?? '',
  };
}

export function badge(s) {
  if (!s.grade)
    return { schemaVersion: 1, label: 'ironheights', message: 'not scanned', color: 'lightgrey' };
  return {
    schemaVersion: 1,
    label: 'ironheights',
    message: `${s.grade} (${s.score}/100)`,
    color: COLORS[s.grade] ?? 'lightgrey',
  };
}

function esc(t) {
  return String(t ?? '')
    .replace(/\|/g, '\\|')
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 160);
}

export function markdown(s) {
  const lines = [
    `## Ironheights: grade ${s.grade || '?'} (${s.score === '' ? '?' : s.score}/100), verdict ${s.verdict || '?'}`,
    '',
    `ironheights ${s.version}. ${s.findings.length} finding(s) in ${s.skills.length} skill(s). Absence of findings is not proof of safety.`,
    '',
  ];
  if (s.findings.length) {
    lines.push('| Severity | Rule | Skill file | Line |', '| --- | --- | --- | --- |');
    for (const f of s.findings.slice(0, 20)) {
      lines.push(
        `| ${esc(f.severity)} | [${esc(f.ruleId)}](https://www.ironheights.dev/rules/${String(f.ruleId ?? '').toLowerCase()}/) | ${esc(f.file)} | ${esc(f.line)} |`,
      );
    }
    if (s.findings.length > 20)
      lines.push('', `${s.findings.length - 20} more in the JSON result.`);
  }
  return lines.join('\n') + '\n';
}

function main() {
  const env = process.env;
  const out = env.GITHUB_OUTPUT;
  let result = null;
  try {
    if (env.IH_JSON && existsSync(env.IH_JSON))
      result = JSON.parse(readFileSync(env.IH_JSON, 'utf8'));
  } catch {
    result = null;
  }
  const s = summarize(result);
  if (out) {
    appendFileSync(
      out,
      `grade=${s.grade}\nscore=${s.score}\nverdict=${s.verdict}\nfindings=${result ? s.findings.length : ''}\n`,
    );
  }
  if (env.IH_BADGE) {
    const p = isAbsolute(env.IH_BADGE)
      ? env.IH_BADGE
      : resolve(env.GITHUB_WORKSPACE ?? '.', env.IH_BADGE);
    writeFileSync(p, JSON.stringify(badge(s), null, 2) + '\n');
  }
  if (env.IH_SUMMARY !== 'false' && env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      env.GITHUB_STEP_SUMMARY,
      result ? markdown(s) : 'Ironheights did not produce a JSON result.\n',
    );
  }
  if (result) console.log(result.summary ?? '');
}

if (import.meta.url === `file://${process.argv[1]}`) main();
