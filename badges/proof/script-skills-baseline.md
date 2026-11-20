# shipped-script skills baseline

Multi-file skills whose malice (or the honest twin's lack of it) lives in a shipped script. Ironheights main is 0.36.0 (`590ac5f`). Cisco has no review tier (MEDIUM+ counted as review). SkillSpector run with `--no-llm`. Held-out was scored once and not used to tune rules. Nothing was executed.

### all (1028 attacks, 1026 benign)

| Scanner | Attacks blocked | Block or review | Missed | Benign wrongly blocked | Benign block-or-review |
|---|---|---|---|---|---|
| Ironheights PR (0.36.0) | 533/1028 | 694/1028 | 334/1028 | 0/1026 | 112/1026 |
| Cisco skill-scanner 2.3.2 | 342/1028 | 415/1028 | 613/1028 | 231/1026 | 288/1026 |
| NVIDIA SkillSpector v2.12.0 | 295/1028 | 703/1028 | 325/1028 | 225/1026 | 693/1026 |

### dev (489 attacks, 533 benign)

| Scanner | Attacks blocked | Block or review | Missed | Benign wrongly blocked | Benign block-or-review |
|---|---|---|---|---|---|
| Ironheights PR (0.36.0) | 242/489 | 322/489 | 167/489 | 0/533 | 57/533 |
| Cisco skill-scanner 2.3.2 | 168/489 | 199/489 | 290/489 | 120/533 | 154/533 |
| NVIDIA SkillSpector v2.12.0 | 141/489 | 335/489 | 154/489 | 117/533 | 362/533 |

### heldout (539 attacks, 493 benign)

| Scanner | Attacks blocked | Block or review | Missed | Benign wrongly blocked | Benign block-or-review |
|---|---|---|---|---|---|
| Ironheights PR (0.36.0) | 291/539 | 372/539 | 167/539 | 0/493 | 55/493 |
| Cisco skill-scanner 2.3.2 | 174/539 | 216/539 | 323/539 | 111/493 | 134/493 |
| NVIDIA SkillSpector v2.12.0 | 154/539 | 368/539 | 171/539 | 108/493 | 331/493 |
