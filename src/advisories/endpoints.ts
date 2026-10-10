/** Pinned advisory feed. The CLI never accepts a different host. */
export const ADVISORY_HOST = 'ironheights.dev';
export const ADVISORY_FEED_URL = `https://${ADVISORY_HOST}/advisories.json`;
export const ADVISORY_FEED_SIG_URL = `https://${ADVISORY_HOST}/advisories.json.sig`;

export const ADVISORY_JSON_MAX_BYTES = 5 * 1024 * 1024;
export const ADVISORY_SIG_MAX_BYTES = 4096;
