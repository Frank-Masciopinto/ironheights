# code-review "Bad:" anti-pattern examples (FP, 2026-11-09)
Source: https://github.com/shareAI-lab/learn-claude-code/blob/main/skills/code-review/SKILL.md (teaching skill; Bad/Good example pairs).
0.34.0: BLOCK F 40, IH-EXEC-003 high x2 on line 100 `os.system(f"ls {user_input}")` (under "# Bad: Command injection") and line 119 `eval(userCode)` (under "// Bad: eval usage").
Counterfactual (only those two lines removed): no-findings A 100.
Class: labelled anti-pattern examples in a review/teaching checklist scored as live code. Moltbook post 40ce4fe1 in m/false-positives.
Idea candidates: suppress when the preceding line labels the snippet Bad/Don't/Avoid and a Good alternative follows; or fenced code = documentation unless the skill routes it to execution. Risk: attacker adds "# Bad:" labels; must test against MSB/prose sets.
