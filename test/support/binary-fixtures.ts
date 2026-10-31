import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Binary-looking fixtures for IH-BIN-001/IH-BIN-002 are generated at test time
// instead of being committed, so the repository ships no binary artifacts
// (OpenSSF Scorecard Binary-Artifacts). Bytes are identical to the old files.
const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'malicious');

export const binaryFixtures: Record<string, string | Uint8Array> = {
  'IH-BIN-001/payload.exe': 'not a real program\n',
  'IH-BIN-001/library.so': 'not a real library\n',
  'IH-BIN-001/setup.zip': Uint8Array.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]),
  'IH-BIN-001/elf.bin': Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
  'IH-BIN-002/Main.class': Uint8Array.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]),
  'IH-BIN-002/addon.wasm': Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
  'IH-BIN-002/tool.cpython-312.pyc': Uint8Array.from([
    0xcb, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00,
  ]),
};

export function writeBinaryFixtures(): void {
  for (const [rel, contents] of Object.entries(binaryFixtures)) {
    const file = join(root, rel);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, contents);
  }
}

export default function setup(): void {
  writeBinaryFixtures();
}
