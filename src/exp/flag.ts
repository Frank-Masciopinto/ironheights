/** Local experiment gate (not for merge): IH_EXP=F,G,... */
export function expOn(key: string): boolean {
  const raw = typeof process !== 'undefined' ? (process.env.IH_EXP ?? '') : '';
  return raw.split(',').map((s) => s.trim()).includes(key);
}
