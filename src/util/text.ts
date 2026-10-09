const ANSI = new RegExp(`${String.fromCharCode(0x1b)}\\[[0-?]*[ -/]*[@-~]`, 'g');
const CONTROLS = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(8)}${String.fromCharCode(11)}${String.fromCharCode(12)}${String.fromCharCode(14)}-${String.fromCharCode(31)}${String.fromCharCode(127)}]`,
  'g',
);

/** Strip ANSI escapes and ASCII control characters from untrusted text. */
export function stripControls(value: string): string {
  return value.replace(ANSI, '').replace(CONTROLS, '');
}

export function clip(value: string, max = 200): string {
  const clean = stripControls(value).replace(/\s+/g, ' ').trim();
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max - 3)}...`;
}

export function eachLine(text: string, visit: (line: string, lineNumber: number) => void): void {
  const parts = text.split(/\r?\n/);
  for (let i = 0; i < parts.length; i += 1) {
    const raw = parts[i] ?? '';
    for (const chunk of chunks(raw)) {
      visit(chunk, i + 1);
    }
  }
}

function chunks(line: string): string[] {
  const size = 4000;
  const overlap = 200;
  if (line.length <= size) return [line];
  const out: string[] = [];
  for (let i = 0; i < line.length; i += size - overlap) {
    out.push(line.slice(i, i + size));
    if (i + size >= line.length) break;
  }
  return out;
}

export function normalizeMatch(text: string): string {
  return text
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF]/g, '')
    .replace(/\s+/g, ' ')
    .toLowerCase();
}
