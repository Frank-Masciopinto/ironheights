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

/** Destinations that raise IH-NET-001 from medium to high. */
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

export const BAD_HOST_MARKERS = [
  'webhook.site',
  'bit.ly',
  'pastebin',
  'ngrok',
  'duckdns',
  'tinyurl',
] as const;
