export function colorEnabled(noColorFlag: boolean, env: NodeJS.ProcessEnv = process.env): boolean {
  if (noColorFlag) return false;
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') return false;
  return true;
}

export function paint(enabled: boolean, code: string, text: string): string {
  if (!enabled) return text;
  return `\u001b[${code}m${text}\u001b[0m`;
}
