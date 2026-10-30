import { describe, expect, it } from 'vitest';
// @ts-expect-error plain ESM script without types
import { badge, markdown, summarize } from '../scripts/action-report.mjs';

const result = {
  tool: { name: 'ironheights', version: '0.17.0' },
  verdict: 'block',
  grade: { letter: 'F', score: 0 },
  skills: [
    {
      skillName: 's',
      findings: [{ ruleId: 'IH-CRED-001', severity: 'high', file: 'SKILL.md', line: 3 }],
    },
  ],
};

describe('action report', () => {
  it('summarizes grade, verdict and findings', () => {
    const s = summarize(result);
    expect(s.grade).toBe('F');
    expect(s.score).toBe(0);
    expect(s.verdict).toBe('block');
    expect(s.findings).toHaveLength(1);
  });
  it('writes a shields.io endpoint badge', () => {
    expect(badge(summarize(result))).toEqual({
      schemaVersion: 1,
      label: 'ironheights',
      message: 'F (0/100)',
      color: 'red',
    });
    expect(badge(summarize(null)).message).toBe('not scanned');
  });
  it('links each finding to its rule page and escapes table cells', () => {
    const md = markdown(
      summarize({
        ...result,
        skills: [
          { findings: [{ ruleId: 'IH-CRED-001', severity: 'high', file: 'a|b.md', line: 1 }] },
        ],
      }),
    );
    expect(md).toContain('https://www.ironheights.dev/rules/ih-cred-001/');
    expect(md).toContain('a\\|b.md');
  });
});
