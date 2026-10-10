import { generateKeyPairSync } from 'node:crypto';
import { chmodSync, writeFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';

const args = process.argv.slice(2);

function arg(name) {
  const index = args.indexOf(name);
  if (index === -1 || !args[index + 1]) {
    console.error(`missing ${name}`);
    process.exit(64);
  }
  return args[index + 1];
}

const out = arg('--out');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pubDer = publicKey.export({ format: 'der', type: 'spki' });
const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
const publicHex = Buffer.from(pubDer.subarray(pubDer.length - 32)).toString('hex');
const seed = Buffer.from(privDer.subarray(privDer.length - 32)).toString('hex');
const body = `# Advisory feed private key. Do not commit this file.\n${seed}\n`;
writeFileSync(out, body, { mode: 0o600 });
chmodSync(out, 0o600);
console.error(`wrote ${out}`);
console.error(`public key: ${publicHex}`);
console.error('Put the public key in src/advisories/pinned-key.ts. Keep the private key offline.');
