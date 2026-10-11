export const DEFAULT_GUARD_PRIORITY = 80;

/**
 * `before_tool_call` order. OpenClaw runs higher priorities first (the
 * default is 0) and a block ends the chain. A value that is not an integer
 * from -1000 to 1000 falls back to the default.
 */
export function priorityFromConfig(config: unknown): number {
  if (!config || typeof config !== 'object' || !('priority' in config)) {
    return DEFAULT_GUARD_PRIORITY;
  }
  const value = (config as { priority?: unknown }).priority;
  if (typeof value !== 'number' || !Number.isInteger(value)) return DEFAULT_GUARD_PRIORITY;
  if (value < -1000 || value > 1000) return DEFAULT_GUARD_PRIORITY;
  return value;
}
