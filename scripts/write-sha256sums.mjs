import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const files = process.argv.slice(2).sort();
if (files.length === 0) {
  console.error('usage: node scripts/write-sha256sums.mjs <file>...');
  process.exit(64);
}
for (const file of files) {
  const hash = createHash('sha256').update(readFileSync(file)).digest('hex');
  process.stdout.write(`${hash}  ${basename(file)}\n`);
}
