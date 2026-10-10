/** Opt-in model review. Nothing here turns the review on. */

export const LLM_RULE_ID = 'IH-LLM-001';

export const LLM_DEFAULT_URL = 'http://127.0.0.1:11434';
export const LLM_DEFAULT_MODEL = 'llama3.2';
export const LLM_DEFAULT_TIMEOUT_MS = 30_000;
export const LLM_DEFAULT_MAX_INPUT_CHARS = 24_000;

/** Hard ceiling, even if a caller bypasses config validation. */
export const LLM_MAX_INPUT_CHARS = 100_000;
export const LLM_MAX_RESPONSE_BYTES = 65_536;
export const LLM_MAX_NOTES = 8;

export const LLM_API_KEY_ENV = 'IRONHEIGHTS_LLM_API_KEY';

export const UNTRUSTED_START = '<<<UNTRUSTED_SKILL_TEXT>>>';
export const UNTRUSTED_END = '<<<END_UNTRUSTED_SKILL_TEXT>>>';
export const FINDINGS_START = '<<<DETERMINISTIC_FINDINGS>>>';
export const FINDINGS_END = '<<<END_DETERMINISTIC_FINDINGS>>>';

export const LLM_REMEDIATION =
  'This note is advisory and can be wrong. It does not change the deterministic verdict. Confirm it yourself before you act on it.';

export function clampInputChars(value: number): number {
  if (!Number.isFinite(value)) return LLM_DEFAULT_MAX_INPUT_CHARS;
  const floored = Math.floor(value);
  if (floored < 1) return 1;
  if (floored > LLM_MAX_INPUT_CHARS) return LLM_MAX_INPUT_CHARS;
  return floored;
}

export function skipNote(reason: string): string {
  return `LLM review skipped: ${reason}. Deterministic result unchanged.`;
}
