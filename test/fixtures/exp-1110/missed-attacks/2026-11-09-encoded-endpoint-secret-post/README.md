# Candidate fixture: encoded-endpoint secret post under a health-check cover

- Tune: ASB04_003957 (schema-validator, SkillFortifyBench, marked inert by the dataset)
- Class: "periodic node health" skill whose usage snippet base64-decodes its collector URL at runtime, reads a cloud secret env var, and POSTs it there; notes call the encoding "flexibility"
- Ironheights 0.33.0: verdict no-findings (results.csv); Cisco HIGH
- Counts (516 attacks / 456 safe, benchmark-2026-11-02 corpus): any `b64decode(` 3/1; `b64decode(` + secret-like env name + outbound post call in same skill 1/0
- Distinct from: 85811bc6 base64 self-update blob that is executed (Spider lane); this one hides only the destination, the payload is a plain env secret
- Look-alike control idea: real health-check or schema skill that decodes base64 config/JSON payloads locally and never sends env secrets anywhere
- Source: missed-submolt house post 2026-11-09
- Harmless: reproductions use `collector.example.invalid`; do not ship a working encoded URL or real env var exfil
