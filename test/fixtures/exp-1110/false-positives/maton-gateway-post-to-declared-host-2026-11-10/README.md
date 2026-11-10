# zoom-api (Maton gateway): POST to the skill's own declared gateway host = BLOCK (FP, 2026-11-10)
Source: clawhub:byungkyu/zoom-api@1.0.6 (in the 275/5655 realworld-clean blocked list, reason "score", 0.33.0 gate). Local copy /workspace/ih-lookalike-batch/ALL/zoom-api.
Skill declares Maton managed OAuth in description, homepage maton.ai, requires.env MATON_API_KEY; all calls go to gateway.maton.ai / ctrl.maton.ai.
ironheights 0.34.0:
- original: BLOCK F 35 = 2x IH-NET-002 high (L92 POST ctrl.maton.ai/connections, L283 POST gateway.maton.ai/zoom/v2/users/me/meetings; "Sensitive data and an outbound request appear in the same few lines") + META-001 low.
- variants/get-only (POST/PUT/PATCH bodies dropped, GETs unchanged): no-findings A 95.
- variants/planted-offbrand (one POST host swapped to zoom-meeting-sync.io, never declared): BLOCK F 20 (NET-002 x2 + NET-001 medium). Rule barely separates declared vs undeclared host.
Family: 35 of the 275 realworld-clean blocks (0.33.0) are byungkyu Maton gateway skills; spot-check on 0.34.0 box F30, pdf-co F40, zoho-bookings F20, buffer-api F35 (17x NET-002), jobber F25, reducto F40, whatsapp-business F10 — all NET-002 high.
Class: IH-NET-002 key+outbound proximity fires on POST to the host the skill declares (description/homepage/requires.env key name matches host brand).
Fix idea (not implemented, no PR): demote NET-002 when the request host matches a host/domain declared in frontmatter (homepage/description) and the secret is the declared requires.env key; keep full severity for undeclared hosts. Must pass full benchmark + look-alike gate + DISCARDED-RULES check (cf. 2026-10-23 brand-middleman rule-candidate).
