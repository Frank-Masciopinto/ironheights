import { mkdir, writeFile } from 'node:fs/promises';
import { renderRulesDocument } from '../src/rules/docs.ts';

const target = new URL('../docs/rules.md', import.meta.url);
await mkdir(new URL('../docs/', import.meta.url), { recursive: true });
await writeFile(target, renderRulesDocument());
console.log('wrote docs/rules.md');
