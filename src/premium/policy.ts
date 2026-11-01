/**
 * Policy templates (0.26.0, Team / Fleet track, open and opt-in).
 *
 * `ironheights policy init --template <name>` writes a scanner config and a guard policy.
 * Every template is at least as strict as the defaults: none raises a threshold, disables a
 * rule, adds a suppression or allows a domain. Templates only tighten.
 */
import { DEFAULT_THRESHOLDS, type ConfigInput } from '../core/config.ts';
import type { GuardPolicyFile } from '../guard/load.ts';

export interface PolicyTemplate {
  name: string;
  description: string;
  config: ConfigInput;
  guard: GuardPolicyFile;
  /** Extra files (relative path -> contents), e.g. a CI workflow. */
  extra?: Record<string, string>;
}

const CI_WORKFLOW = `name: ironheights
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx -y ironheights scan . --config ironheights.config.json --fail-on high
      - run: npx -y ironheights report . --fail-on-incomplete
      - run: npx -y ironheights threatmodel check --fail-on-widen
`;

export const TEMPLATES: Record<string, PolicyTemplate> = {
  balanced: {
    name: 'balanced',
    description: 'defaults made explicit: fail on high, guard in monitor mode',
    config: { failOn: 'high', thresholds: { ...DEFAULT_THRESHOLDS } },
    guard: { version: 1, mode: 'monitor' },
  },
  strict: {
    name: 'strict',
    description: 'fail on medium, lower block/review thresholds, guard enforces',
    config: {
      failOn: 'medium',
      thresholds: { block: 40, review: 5 },
      suppressCritical: false,
      suppressIntegrity: false,
    },
    guard: { version: 1, mode: 'enforce' },
  },
  ci: {
    name: 'ci',
    description:
      'for pipelines: fail on high, guard enforces, GitHub Actions workflow with CI gates',
    config: { failOn: 'high', thresholds: { ...DEFAULT_THRESHOLDS } },
    guard: { version: 1, mode: 'enforce' },
    extra: { '.github/workflows/ironheights.yml': CI_WORKFLOW },
  },
};
