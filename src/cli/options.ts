import { UsageError } from '../core/errors.ts';
import type { Severity } from '../core/types.ts';

export function parseFailOn(value: string): Severity {
  switch (value) {
    case 'info':
    case 'low':
    case 'medium':
    case 'high':
    case 'critical':
      return value;
    default:
      throw new UsageError('--fail-on must be info, low, medium, high, or critical');
  }
}
