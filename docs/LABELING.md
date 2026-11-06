# Where the labels come from

Ironheights reports detection and false-positive rates on sets it did not label itself. This page says who labeled each set, and what that label does not mean.

| Set | Where the label comes from | What we assume | Known caveat |
| --- | --- | --- | --- |
| MaliciousSkillBench malicious rows (`bench/msb`, 516) | Upstream benchmark label on the pinned Hugging Face revision in `bench/msb/manifest.json` | The upstream `malicious` label is the positive class | The prose/code tag in the manifest is a regex (a code fence counts as code). A plain-language attack inside a workflow can still be tagged `code`. |
| MaliciousSkillBench benign rows (456) | Upstream benchmark label on the same revision | The upstream `benign` label is the negative class | Some rows are security tools or attack write-ups. A hit can be a true description of an attack, which still counts as a false positive for a scanner that cannot tell a write-up from an instruction. |
| Anthropic skills (19, inside the benign count) | No malice label. `anthropics/skills` at the commit in the manifest, treated as clean | Assumed clean | They are real project skills, not a random sample of all skills, and they were not independently audited for this repo. |
| Real-world clean corpus (`bench/realworld`, 5,655) | No upstream malice label. ClawHub skills kept only when ClawScan, static analysis, VirusTotal, and NVIDIA SkillSpector all said clean, plus GitHub `SKILL.md` files from repositories with at least 5,000 stars | Assumed clean, with a reviewed baseline of the skills current `main` already blocks or sends to review | "All four tools said clean" is not proof the skill is safe. The baseline is a list of known scanner hits, not a finding that those skills are malicious. The corpus stores hashes, not the skill text. |
| Blind held-out set (`bench/blind`, 600 malicious / 300 benign) | A fixed slice of MaliciousSkillBench, disjoint from `bench/msb`, chosen by hash | Same upstream labels as MaliciousSkillBench | Totals only. Skill text, ids, and evidence from this set are not used to write or tune rules. |
| House fixtures (`bench/house`) | Written in this repo as defanged attack/control pairs | The `attack` directory is the positive class and the control or twin is the negative class | These numbers are not part of the public MaliciousSkillBench score. A rule can pass every house pair and still be overfit. |

A scanner `review` means inspect this; it is not a malicious verdict. A clean result means no known pattern was found; it is not proof of safety.

## Draft note for an outside reviewer

This paragraph is a draft for Kaleb to send later. It has not been posted.

> Ironheights publishes a one-command benchmark (`npm run bench`) that downloads pinned skill text, checks SHA-256, and writes per-sample verdicts for the public sets. The blind set is totals and a digest only. Labels come from MaliciousSkillBench upstream, from treating the Anthropic skills and the real-world registry sample as clean, and from a reviewed baseline of known scanner hits. I would like a second person to run that command and file any disagreement as an issue: a row you would label differently, or a verdict you think the scanner got wrong. House fixtures under `bench/house` are not part of the published score.
