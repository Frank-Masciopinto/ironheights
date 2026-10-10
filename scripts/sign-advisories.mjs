import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const args = process.argv.slice(2);

function arg(name) {
  const index = args.indexOf(name);
  if (index === -1 || !args[index + 1]) {
    console.error(`missing ${name}`);
    process.exit(64);
  }
  return args[index + 1];
}

const sourcePath = arg('--source');
const keyPath = arg('--key');
const outPath = arg('--out');

const source = JSON.parse(readFileSync(sourcePath, 'utf8'));
const advisories = Array.isArray(source.advisories) ? source.advisories : null;
if (!advisories || typeof source.generatedAt !== 'string') {
  console.error('source must contain generatedAt and advisories');
  process.exit(64);
}

const document = {
  schemaVersion: 1,
  generatedAt: source.generatedAt,
  advisories: advisories
    .map(canonicalAdvisory)
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0)),
};
const json = `${JSON.stringify(document, null, 2)}\n`;
const seed = readSeed(keyPath);
const privateKey = createPrivateKey({
  key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
  format: 'der',
  type: 'pkcs8',
});
const signature = sign(null, Buffer.from(json), privateKey);
const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const publicHex = Buffer.from(publicDer.subarray(publicDer.length - 32)).toString('hex');
writeFileSync(outPath, json);
writeFileSync(`${outPath}.sig`, `ed25519 ${signature.toString('base64')}\n`);
console.error(`public key: ${publicHex}`);
console.error(`wrote ${outPath} and ${outPath}.sig`);

function canonicalAdvisory(entry) {
  return {
    id: entry.id,
    skill: entry.skill,
    ...(entry.owner ? { owner: entry.owner } : {}),
    versions: [...(entry.versions ?? [])].sort(),
    contentHashes: (entry.contentHashes ?? [])
      .map((hash) =>
        String(hash)
          .replace(/^sha256:/, '')
          .toLowerCase(),
      )
      .sort(),
    campaign: entry.campaign,
    iocHosts: (entry.iocHosts ?? []).map((host) => String(host).toLowerCase()).sort(),
    sources: [...(entry.sources ?? [])].sort(),
    firstSeen: entry.firstSeen,
    status: entry.status,
  };
}

function readSeed(filePath) {
  const text = readFileSync(filePath, 'utf8');
  const line = text
    .split(/\r?\n/)
    .map((item) => item.trim())
    .find((item) => item.length > 0 && !item.startsWith('#'));
  if (!line || !/^[0-9a-f]{64}$/i.test(line)) {
    console.error('private key file must contain one 32-byte hex seed');
    process.exit(64);
  }
  return Buffer.from(line, 'hex');
}
