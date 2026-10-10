import { timingSafeEqual } from 'node:crypto';
import { NetworkError, UsageError } from '../../core/errors.ts';
import { ironheightsHome } from '../../core/config.ts';
import {
  readAdvisoryCache,
  removePartialAdvisoryWrite,
  writeAdvisoryCache,
} from '../../advisories/cache.ts';
import { verifyAdvisorySignature } from '../../advisories/crypto.ts';
import {
  ADVISORY_FEED_SIG_URL,
  ADVISORY_FEED_URL,
  ADVISORY_HOST,
  ADVISORY_JSON_MAX_BYTES,
  ADVISORY_SIG_MAX_BYTES,
} from '../../advisories/endpoints.ts';
import { pinnedAdvisoryPublicKey } from '../../advisories/pinned-key.ts';
import { parseAdvisoryDocument } from '../../advisories/schema.ts';
import { formatRequestPlan, pinnedGet } from '../../net/http.ts';
import { NETWORK_BANNER } from '../../net/clawhub.ts';

export interface AdvisoriesFlags {
  env?: NodeJS.ProcessEnv;
  stdout?: (text: string) => void;
  fetchImpl?: typeof fetch;
  /** Test hook. The CLI does not accept an alternate advisory key. */
  publicKey?: Uint8Array | null;
}

export async function runAdvisories(
  action: string | undefined,
  flags: AdvisoriesFlags = {},
): Promise<number> {
  if (action === 'update') return updateAdvisories(flags);
  if (action === 'show') return showAdvisories(flags);
  throw new UsageError('advisories requires update or show');
}

async function updateAdvisories(flags: AdvisoriesFlags): Promise<number> {
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  const home = ironheightsHome(flags.env ?? process.env);
  const publicKey = flags.publicKey !== undefined ? flags.publicKey : pinnedAdvisoryPublicKey();
  write('advisories update\n');
  write(NETWORK_BANNER);
  write(formatRequestPlan([ADVISORY_FEED_URL, ADVISORY_FEED_SIG_URL]));
  const feed = await pinnedGet(ADVISORY_FEED_URL, ADVISORY_HOST, {
    maxBytes: ADVISORY_JSON_MAX_BYTES,
    ...(flags.fetchImpl ? { fetchImpl: flags.fetchImpl } : {}),
  });
  const sig = await pinnedGet(ADVISORY_FEED_SIG_URL, ADVISORY_HOST, {
    maxBytes: ADVISORY_SIG_MAX_BYTES,
    ...(flags.fetchImpl ? { fetchImpl: flags.fetchImpl } : {}),
  });
  let jsonText: string;
  let sigText: string;
  try {
    jsonText = new TextDecoder('utf-8', { fatal: true }).decode(feed.body);
    sigText = new TextDecoder('utf-8', { fatal: true }).decode(sig.body);
  } catch {
    throw new NetworkError('advisory feed is not valid UTF-8');
  }
  if (!publicKey) {
    throw new NetworkError(
      'The production advisory public key is not configured (src/advisories/pinned-key.ts). Refusing to trust the feed.',
    );
  }
  const reencoded = new TextEncoder().encode(jsonText);
  if (
    reencoded.byteLength !== feed.body.byteLength ||
    !timingSafeEqual(Buffer.from(reencoded), Buffer.from(feed.body))
  ) {
    throw new NetworkError('advisory feed is not stable UTF-8');
  }
  if (!verifyAdvisorySignature(feed.body, sigText, publicKey)) {
    throw new NetworkError('Advisory feed signature is invalid. The cache was not changed.');
  }
  const document = parseAdvisoryDocument(jsonText);
  try {
    const paths = await writeAdvisoryCache(home, jsonText, sigText);
    write(
      `Advisory feed signature verified.\nCached ${document.advisories.length} advisories generated at ${document.generatedAt}\nWrote ${paths.jsonPath}\n`,
    );
  } catch (error) {
    await removePartialAdvisoryWrite(home);
    throw error;
  }
  return 0;
}

async function showAdvisories(flags: AdvisoriesFlags): Promise<number> {
  const write = flags.stdout ?? ((text: string) => process.stdout.write(text));
  const home = ironheightsHome(flags.env ?? process.env);
  const publicKey = flags.publicKey !== undefined ? flags.publicKey : pinnedAdvisoryPublicKey();
  const cache = await readAdvisoryCache(home, publicKey);
  if (cache.status === 'missing') {
    write('No advisory cache. Run `ironheights advisories update` to fetch one.\n');
    return 0;
  }
  if (cache.status === 'rejected') throw new NetworkError(cache.message);
  write(
    `generatedAt: ${cache.document.generatedAt}\nentries: ${cache.document.advisories.length}\n`,
  );
  for (const advisory of cache.document.advisories) {
    write(`${advisory.id}\t${advisory.skill}\t${advisory.status}\t${advisory.campaign}\n`);
  }
  return 0;
}
