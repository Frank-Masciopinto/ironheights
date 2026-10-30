import { describeDependency } from '../../core/dependencies.ts';
import {
  formatGrade,
  gradeFromSkills,
  incompleteScanLine,
  renderBadge,
  renderSummary,
  TEXT_SCAN_LIMIT,
} from '../../core/grade.ts';
import type { ScanMode } from '../../core/grade.ts';
import type { AdvisoryFeedNote, Finding, SkillReport, Verdict } from '../../core/types.ts';
import { acceptanceLabel } from '../../core/suppress.ts';
import { blockingDirectoryCount } from '../../core/verdict.ts';
import type { LlmReviewReport } from '../../llm/review.ts';
import { openCreUrl, referencesFor, referenceTags } from '../../rules/references.ts';
import { SAFETY_REMINDER, TOOL_VERSION } from '../../version.ts';
import { llmStatusLines } from './llm-status.ts';

const STYLE = `
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; color: #1c1917; background: #fff; line-height: 1.45; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  .grade { font-size: 1.1rem; margin: 0.25rem 0; }
  .disclaimer { margin-top: 0; }
  pre { white-space: pre-wrap; background: #f5f5f4; padding: 0.75rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #d6d3d1; text-align: left; vertical-align: top; padding: 0.35rem 0.5rem; }
  th { background: #f5f5f4; }
  .sev-critical, .sev-high { color: #9f1239; }
  .sev-medium { color: #92400e; }
  .sev-low, .sev-info { color: #44403c; }
  .note { color: #44403c; }
`.trim();

export function renderHtml(
  skills: SkillReport[],
  verdict: Verdict,
  scannedAt: string,
  scanMode: ScanMode = 'directory',
  advisory?: AdvisoryFeedNote,
  llmReview?: LlmReviewReport,
): string {
  const grade = gradeFromSkills(skills);
  const summary = renderSummary({ skills, verdict, grade, scanMode });
  const badge = renderBadge({ skills, verdict, grade, scanMode });
  const parts: string[] = [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="referrer" content="no-referrer">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`,
    `<title>${escapeHtml(`Ironheights ${TOOL_VERSION} report`)}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    '<h1>Ironheights report</h1>',
    `<p>Scanned at ${escapeHtml(scannedAt)}</p>`,
  ];
  if (scanMode === 'text') parts.push(`<p class="note">${escapeHtml(TEXT_SCAN_LIMIT)}</p>`);
  if (advisory) {
    parts.push(
      `<p class="note">${escapeHtml(`Advisory feed: ${advisory.entries} entries, generated ${advisory.generatedAt}.`)}</p>`,
    );
  }
  parts.push(
    `<p>Verdict: ${escapeHtml(verdict)}</p>`,
    `<p class="grade">Grade: ${escapeHtml(formatGrade(grade))}</p>`,
    ...llmStatusLines(skills, llmReview).map((line) => `<p class="note">${escapeHtml(line)}</p>`),
    `<p class="disclaimer">${escapeHtml(SAFETY_REMINDER)}</p>`,
    `<pre>${escapeHtml(summary)}</pre>`,
    '<p>README badge</p>',
    `<pre>${escapeHtml(badge)}</pre>`,
  );
  for (const skill of skills) {
    parts.push(`<h2>${escapeHtml(skill.skillName)}</h2>`);
    parts.push(`<p>Root: ${escapeHtml(skill.root)}</p>`);
    parts.push(
      `<p>Score: ${escapeHtml(String(skill.score))}. Verdict: ${escapeHtml(skill.verdict)}</p>`,
    );
    parts.push(findingsTable(skill.findings));
    parts.push(
      simpleList(
        'Suppressed',
        (skill.suppressed ?? []).map(
          (item) => `${item.ruleId} ${place(item)} reason=${item.reason}`,
        ),
      ),
    );
    parts.push(
      simpleList(
        'Suppression refused',
        (skill.suppressionRefused ?? []).map(
          (item) => `${item.ruleId} ${place(item)} ${item.detail}`,
        ),
      ),
    );
    parts.push(simpleList('Suppression ignored', skill.suppressionWarnings ?? []));
    parts.push(
      simpleList(
        'Stale suppression',
        (skill.staleSuppressions ?? []).map((item) => {
          const wherePath = item.path ?? '*';
          return `${item.ruleId} ${wherePath} evidence=${item.evidence} reason=${item.reason}`;
        }),
      ),
    );
    parts.push(
      simpleList(
        'Omitted as pre-existing',
        (skill.sinceBaseline?.omitted ?? []).map((item) => `${item.ruleId} ${place(item)}`),
      ),
    );
    parts.push(
      simpleList(
        'Dependencies unscanned',
        (skill.unscannedDependencies ?? []).map((dep) => describeDependency(dep)),
      ),
    );
    parts.push(
      simpleList(
        'Skipped files',
        skill.filesSkipped.map((item) => `${item.file} (${item.reason})`),
      ),
    );
    parts.push(
      simpleList(
        'Skipped directories',
        (skill.skippedDirectories ?? []).map((item) =>
          item.explicit
            ? `ignored ${item.path} (${item.reason})`
            : `warning: skipped directory ${item.path} (${item.reason})`,
        ),
      ),
    );
    if (skill.verdict === 'incomplete') {
      parts.push(
        `<p>${escapeHtml(incompleteScanLine(skill.filesSkipped.length, blockingDirectoryCount(skill)))}</p>`,
      );
    }
  }
  parts.push(`<p class="disclaimer">${escapeHtml(SAFETY_REMINDER)}</p>`, '</body>', '</html>', '');
  return parts.join('\n');
}

function findingsTable(findings: Finding[]): string {
  if (findings.length === 0) return '<p>No findings in this section.</p>';
  const rows = findings.map((finding) => {
    const tags = referenceTags(finding.ruleId).join(', ');
    const drift = finding.acceptance ? ` (${acceptanceLabel(finding.acceptance)})` : '';
    return `<tr><td class="${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.ruleId)}</td><td>${escapeHtml(place(finding))}</td><td>${escapeHtml(finding.evidence)}</td><td>${escapeHtml(finding.message)}${escapeHtml(drift)}</td><td>${escapeHtml(tags)}${creLinks(finding.ruleId)}</td></tr>`;
  });
  return `<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Evidence</th><th>Message</th><th>References</th></tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

function creLinks(ruleId: string): string {
  const ids = referencesFor(ruleId).openCre;
  if (ids.length === 0) return '';
  const anchors = ids.map(
    (id) => `<a href="${escapeHtml(openCreUrl(id))}" rel="noopener">CRE ${escapeHtml(id)}</a>`,
  );
  return `${tagsSeparator(ruleId)}${anchors.join(', ')}`;
}

function tagsSeparator(ruleId: string): string {
  return referenceTags(ruleId).length > 0 ? ', ' : '';
}

function simpleList(title: string, items: string[]): string {
  if (items.length === 0) return '';
  const lis = items.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
  return `<h3>${escapeHtml(title)} (${items.length})</h3><ul>${lis}</ul>`;
}

function place(item: { file: string; line?: number }): string {
  return item.line ? `${item.file}:${item.line}` : item.file;
}

function severityClass(severity: Finding['severity']): string {
  switch (severity) {
    case 'critical':
      return 'sev-critical';
    case 'high':
      return 'sev-high';
    case 'medium':
      return 'sev-medium';
    case 'low':
      return 'sev-low';
    case 'info':
      return 'sev-info';
    default: {
      const neverSeverity: never = severity;
      return neverSeverity;
    }
  }
}

/** Escape every character that could leave a text node or an attribute. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
