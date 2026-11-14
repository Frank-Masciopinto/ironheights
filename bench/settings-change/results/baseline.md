# settings-change baseline

Block / review / missed on attacks, and benign wrongly blocked, per split. Cisco has no review tier (MEDIUM+ counted as review). SkillSpector run with `--no-llm`.

### dev

| Scanner | Attacks | Blocked | Review | Missed | Benign | Benign wrongly blocked |
|---|---|---|---|---|---|---|
| Ironheights 0.35.1 | 35 | 0 | 3 | 32 | 32 | 0 |
| Cisco skill-scanner 2.3.2 | 35 | 0 | 0 | 35 | 32 | 0 |
| NVIDIA SkillSpector v2.12.0 | 35 | 0 | 2 | 33 | 32 | 0 |

### heldout

| Scanner | Attacks | Blocked | Review | Missed | Benign | Benign wrongly blocked |
|---|---|---|---|---|---|---|
| Ironheights 0.35.1 | 21 | 0 | 1 | 20 | 23 | 0 |
| Cisco skill-scanner 2.3.2 | 21 | 0 | 0 | 21 | 23 | 0 |
| NVIDIA SkillSpector v2.12.0 | 21 | 0 | 3 | 18 | 23 | 0 |
