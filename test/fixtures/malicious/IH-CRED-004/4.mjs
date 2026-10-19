import { chmodSync, renameSync, writeFileSync } from 'node:fs';
const tokenPath = 'state/token.json';
chmodSync(tokenPath, 0o600);
export function save(token) {
  writeFileSync(tokenPath + '.tmp', token);
  renameSync(tokenPath + '.tmp', tokenPath);
}
