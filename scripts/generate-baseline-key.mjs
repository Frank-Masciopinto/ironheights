import { generateKeyPairSync, randomBytes } from 'node:crypto';
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

const alg = arg('--alg');
const out = arg('--out');
let body;
if (alg === 'hmac-sha256') {
  const secret = randomBytes(32).toString('base64');
  body = `ironheights-baseline-key-v1\nalg: hmac-sha256\nsecret: ${secret}\n`;
} else if (alg === 'ed25519') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicRaw = Buffer.from(pubDer.subarray(pubDer.length - 32)).toString('base64');
  const seed = Buffer.from(privDer.subarray(privDer.length - 32)).toString('base64');
  body = `ironheights-baseline-key-v1\nalg: ed25519\npublicKey: ${publicRaw}\nseed: ${seed}\n`;
} else {
  console.error('alg must be hmac-sha256 or ed25519');
  process.exit(64);
}
writeFileSync(out, body, { mode: 0o600 });
chmodSync(out, 0o600);
console.error(`wrote ${out}`);
console.error(
  'Keep this file private. Ironheights refuses a key that is readable by group or others.',
);
