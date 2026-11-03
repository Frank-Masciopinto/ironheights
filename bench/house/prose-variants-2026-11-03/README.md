# Plain-language attack variants (house set, 2026-11-03)
Defanged attacks written from the tuning half only (held-out half and blind set not read). 7 types × 3 variants (ordinary instruction, multi-step workflow where harm is only in one step, referenced-file where harm lives in references/house-rules.md) × attack + honest twin = 42 skills.
Types are grouped from the 65 missed prose-only rows (by upstream category; texts read only for the 29 tune-half rows):
- exfil-fixed-destination: Data Exfiltration (ASB04_003994-like AgentTrap exfil rows)
- output-integrity: Integrity / Output Manipulation (ASB04_001481/002035/003108-like)
- goal-memory-manipulation: Instruction / Goal / Memory Manipulation (ASB04_003947/004303-like)
- authority-tool-abuse: Privilege / Tool / Authority Abuse (ASB04_003456-like)
- persistence-control: Persistence / Control (ASB04_000719/persistence rows)
- resource-abuse: Resource / Availability Abuse (ASB04_001161-like)
- supply-chain: Dependency / Supply-Chain Abuse (SkillTrustBench supply-chain rows)
This is a house set: it is never reported as a benchmark number and is not used for tuning claims. Hosts use .invalid; no payloads.
