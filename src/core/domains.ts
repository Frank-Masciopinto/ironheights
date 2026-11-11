/** Hosts treated as declared. An entry matches itself and its subdomains. */
export const BUILTIN_ALLOW_DOMAINS = [
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'github.com',
  'githubusercontent.com',
  'npmjs.org',
  'yarnpkg.com',
  'pypi.org',
  'pythonhosted.org',
  'openclaw.ai',
] as const;

/**
 * Destinations that raise IH-NET-001 from medium to high.
 * Paste sites and file-drop hosts count when a skill mentions them in prose.
 */
export const BAD_HOST_SUFFIXES = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'pastebin.com',
  'paste.ee',
  'hastebin.com',
  'dpaste.org',
  'dpaste.com',
  'rentry.co',
  'rentry.org',
  'glot.io',
  'ghostbin.com',
  'ghostbin.co',
  'paste.rs',
  'ix.io',
  '0bin.net',
  'justpaste.it',
  'controlc.com',
  'termbin.com',
  'paste2.org',
  'pastebin.pl',
  'privatebin.net',
  'transfer.sh',
  'file.io',
  'gofile.io',
  'catbox.moe',
  'pixeldrain.com',
  'anonfiles.com',
  'uguu.se',
  'tmpfiles.org',
  'ngrok.io',
  'ngrok.app',
  'ngrok-free.app',
  'localtunnel.me',
  'trycloudflare.com',
  'serveo.net',
  'localhost.run',
  'webhook.site',
  'hooks.slack.com',
  'duckdns.org',
  'no-ip.com',
  'dyndns.org',
  'hopto.org',
] as const;

/**
 * Paste sites and file-drop hosts from BAD_HOST_SUFFIXES. These already raise
 * IH-NET-001 to high. Unlike tunnels, Slack/Telegram webhooks, DynDNS, or raw
 * IPs, they did not appear on the 5,655-skill real-world clean set, so a hit
 * can count for the verdict. A broader "every high IH-NET-001" rule was tried
 * and dropped (21 new real-world reviews). See experiments/DISCARDED-RULES.md.
 */
export const SIGNAL_HOST_SUFFIXES = [
  'pastebin.com',
  'paste.ee',
  'hastebin.com',
  'dpaste.org',
  'dpaste.com',
  'rentry.co',
  'rentry.org',
  'glot.io',
  'ghostbin.com',
  'ghostbin.co',
  'paste.rs',
  'ix.io',
  '0bin.net',
  'justpaste.it',
  'controlc.com',
  'termbin.com',
  'paste2.org',
  'pastebin.pl',
  'privatebin.net',
  'transfer.sh',
  'file.io',
  'gofile.io',
  'catbox.moe',
  'pixeldrain.com',
  'anonfiles.com',
  'uguu.se',
  'tmpfiles.org',
] as const;

/** True when `host` is exactly a suffix, or a subdomain of one. */
export function hostMatchesSuffix(host: string, suffixes: readonly string[]): boolean {
  const normalized = host.toLowerCase();
  return suffixes.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`));
}

export const BAD_HOST_MARKERS = [
  'webhook.site',
  'bit.ly',
  'pastebin',
  'rentry',
  'glot',
  'transfer.sh',
  'ngrok',
  'duckdns',
  'tinyurl',
] as const;
