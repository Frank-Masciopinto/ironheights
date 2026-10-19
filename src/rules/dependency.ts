import type { Rule } from '../core/types.ts';

/**
 * Raised by `scan --check-registry` after asking npm or PyPI about each install name.
 * `check` stays empty so a skill file cannot trip it by mentioning the rule id.
 */
export const dep001: Rule = {
  id: 'IH-DEP-001',
  title: 'Install names a package that does not exist',
  category: 'integrity',
  severity: 'high',
  priority: 'P1',
  description:
    'The skill installs an npm or PyPI package whose name the registry does not know (HTTP 404). Anyone can register that name and ship code that runs on the next install. Checked only with scan --check-registry; an offline or failed lookup is reported as not checked, never as missing.',
  remediation:
    'Fix the package name, or publish and pin the real package. Do not install the skill until the name resolves to the intended publisher.',
  appliesTo: ['markdown'],
  examples: {
    matches: [
      'metadata install entry kind: node, package: name-nobody-registered',
      'npm install -g name-nobody-registered (registry returns 404)',
    ],
    nonMatches: [
      'npm install -g typescript (registry returns 200)',
      'registry lookup timed out (reported as not checked)',
    ],
  },
  check: () => [],
};
