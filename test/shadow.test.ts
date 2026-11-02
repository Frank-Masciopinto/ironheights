import { afterEach, describe, expect, it } from 'vitest';
import type { Finding } from '../src/core/types.ts';
import { verdictFor } from '../src/core/verdict.ts';
import { applyShadow } from '../src/rules/shadow.ts';

const base: Finding = {
  ruleId: 'IH-INTENT-001',
  severity: 'critical',
  confidence: 'high',
  file: 'SKILL.md',
  line: 3,
  evidence: 'x',
  message: 'm',
  remediation: 'r',
  shadowCheck: 'demo-check',
};
const thresholds = { block: 80, review: 15 };

describe('shadow mode', () => {
  afterEach(() => {
    delete process.env.IRONHEIGHTS_SHADOW;
  });

  it('logs a shadow finding as info with would-block and does not change the verdict', () => {
    const f = applyShadow(base, new Set(['demo-check']));
    expect(f.severity).toBe('info');
    expect(f.wouldSeverity).toBe('critical');
    expect(f.note).toMatch(/would be critical/);
    expect(verdictFor([f], thresholds)).toBe('no-findings');
  });

  it('enforces full severity with IRONHEIGHTS_SHADOW=enforce', () => {
    process.env.IRONHEIGHTS_SHADOW = 'enforce';
    const f = applyShadow(base, new Set(['demo-check']));
    expect(f.severity).toBe('critical');
    expect(verdictFor([f], thresholds)).toBe('block');
  });

  it('leaves promoted and unmarked findings alone', () => {
    expect(applyShadow(base, new Set()).severity).toBe('critical');
    const plain: Finding = { ...base };
    delete plain.shadowCheck;
    expect(applyShadow(plain, new Set(['demo-check'])).severity).toBe('critical');
  });
});
