#!/usr/bin/env node
// Pins every ironheights install command in skill/ironheights/SKILL.md to the
// version in package.json. Runs from the npm "version" lifecycle hook.
// Use --check to fail (exit 1) when the pin is out of date, e.g. in CI.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const file = join(root, 'skill/ironheights/SKILL.md');
const before = readFileSync(file, 'utf8');
const pin = `ironheights@${version}`;
const after = before
  .replace(/(npm install -g |npm i -g |npx (?:-y )?)ironheights(?:@[\w.-]+)?/g, `$1${pin}`)
  .replace(/^(\s+package: )ironheights(?:@[\w.-]+)?\s*$/m, `$1${pin}`);

if (process.argv.includes('--check')) {
  if (after !== before) {
    console.error(`SKILL.md install pin is not ${pin}. Run: node scripts/pin-skill-version.mjs`);
    process.exit(1);
  }
  console.log(`SKILL.md pinned to ${pin}`);
} else {
  writeFileSync(file, after);
  console.log(`SKILL.md pinned to ${pin}`);
}
