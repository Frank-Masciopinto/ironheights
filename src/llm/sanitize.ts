import { FINDINGS_END, FINDINGS_START, UNTRUSTED_END, UNTRUSTED_START } from './constants.ts';
import { stripControls } from '../util/text.ts';

const HIDDEN = /[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF\u2028\u2029\u{E0000}-\u{E007F}]/gu;

/** Drop bytes a skill can use to hide or restyle text before it reaches a model. */
export function sanitizeUntrusted(value: string): string {
  return stripControls(value).replace(HIDDEN, '');
}

/**
 * A skill that contains the closing marker must not be able to end the
 * untrusted region early and append its own instructions.
 */
export function neutralizeMarkers(value: string): string {
  return value
    .replaceAll(UNTRUSTED_START, '[[[UNTRUSTED_SKILL_TEXT]]]')
    .replaceAll(UNTRUSTED_END, '[[[END_UNTRUSTED_SKILL_TEXT]]]')
    .replaceAll(FINDINGS_START, '[[[DETERMINISTIC_FINDINGS]]]')
    .replaceAll(FINDINGS_END, '[[[END_DETERMINISTIC_FINDINGS]]]');
}

export function sanitizeLabel(value: string): string {
  return neutralizeMarkers(sanitizeUntrusted(value)).replace(/\s+/g, ' ').trim().slice(0, 200);
}
