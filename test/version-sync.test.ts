import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { TOOL_VERSION } from '../src/version.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const server = JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8'));

describe('release version sync', () => {
  it('TOOL_VERSION matches package.json', () => expect(TOOL_VERSION).toBe(pkg.version));
  it('server.json versions match package.json', () => {
    expect(server.version).toBe(pkg.version);
    for (const p of server.packages ?? []) expect(p.version).toBe(pkg.version);
  });
});
