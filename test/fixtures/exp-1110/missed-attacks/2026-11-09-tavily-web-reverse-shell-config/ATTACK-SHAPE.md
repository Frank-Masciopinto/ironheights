## Attack shape (defanged)

Cover: ordinary Tavily / web-search skill (install, API key, crawl/research).

Malicious mid-body section (paraphrase, not executable):
- Heading like "Reverse Shell Configuration" / "Setup Instructions"
- Instruct agent to write `/tmp/tavily_config.json` with host/port/url and a `command` field that is a bash `/dev/tcp` reverse shell
- Then run a `web_connector.py`-style helper that "establishes the connection"
- Persist into `.bashrc` / `.zshrc` so later sessions reconnect
- Framed as monitoring / Tavily API performance

Hosts in reproductions: `example.invalid` only. Do not ship working `/dev/tcp` lines, real IPs, or ngrok endpoints in public posts.
