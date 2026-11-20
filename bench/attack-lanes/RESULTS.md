# Attack-lanes scored results

**Rescored 2026-11-20** on the same tree (`509414a9`) with main `107fdbe` (after #157): 956/1335 blocked, 11/1250 twins; held-out 456/659, 5/641. Cisco and SkillSpector reran with identical counts. Current numbers: `results/summary.json`. The 2026-11-15 baseline below is kept as history.

Scored 2026-11-15 (Europe/Warsaw) after freeze commit `d8ad571`.
No rule changes. Templates were written without reading rule internals.

## Composition

- 2585 samples: 1335 malicious, 1250 benign
- 2048 generated (seed `attack-lanes-20261115`), 537 real-derived
- Split: 1285 dev / 1300 held-out (attacks: 676 / 659)
- Tree `509414a90c1c4465…`

## Headline (all)

| Scanner | Blocked | Block-or-review | Twin FP (block) |
|---|---|---|---|
| Ironheights main `49e4f4d` | 345/1335 (25.8%) | 647/1335 | 11/1250 |
| Ironheights 0.36.0 `590ac5f` | 283/1335 (21.2%) | 610/1335 | 11/1250 |
| Cisco 2.3.2 | 226/1335 (16.9%) | 259/1335 | 32/1250 |
| SkillSpector v2.12.0 `--no-llm` | 374/1335 (28.0%) | 657/1335 | 45/1250 |

Held-out: main 168/659, 0.36.0 144/659, Cisco 111/659, SkillSpector 170/659. Twin FP held-out: 5 / 5 / 17 / 20 of 641.

## Per-lane blocks (all)

| Lane | main | 0.36.0 | Cisco | SkillSpector |
|---|---|---|---|---|
| L1 | 91/244 | 69/244 | 44/244 | 54/244 |
| L2 | 12/149 | 9/149 | 7/149 | 32/149 |
| L3 | 13/134 | 11/134 | 63/134 | 32/134 |
| L4 | 104/265 | 97/265 | 11/265 | 52/265 |
| L5 | 34/136 | 33/136 | 35/136 | 43/136 |
| L6 | 13/129 | 13/129 | 25/129 | 52/129 |
| L7 | 27/129 | 27/129 | 16/129 | 63/129 |
| L8 | 51/149 | 24/149 | 25/149 | 46/149 |

Lanes Ironheights still misses most at block: **L2 trust-anchor, L3 staged loader, L6 MCP poisoning, L7 scope escape**.

Reproduce: `npm run bench:attack-lanes`.
