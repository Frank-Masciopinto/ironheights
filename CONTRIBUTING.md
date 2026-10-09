# Contributing

## Add a rule

1. Pick an id such as `IH-EXEC-004`. Use the next free number in that category.
2. Add the rule in `src/rules/` as a pure function. It may not read the filesystem, the network, or the clock.
3. Keep each regular expression small. Bound every quantifier. Document the pattern next to the rule.
4. Add at least three positive fixtures under `test/fixtures/malicious/<id>/` and three near misses under `test/fixtures/benign/near/<id>/`.
5. Near misses must stay clean for every rule, because `test/fixtures/benign` is scanned as one skill.
6. URLs in fixtures use `.invalid` or `example.com` only. Do not commit real malware.
7. Extend `src/rules/data/injection-phrases.json` when the rule is a phrase list. Matching is case-insensitive.
8. Run `npm run docs:rules` and commit `docs/rules.md`. Do not edit that file by hand.
9. Run `npm run lint && npm run typecheck && npm test`.

A finding needs a rule id, severity, confidence, file, evidence under 200 characters, a message, and the remediation string. Mask secrets before they reach `evidence`.

## Local checks

Node.js 20 or newer. `.nvmrc` is `20`.

```bash
npm install
npm run lint
npm run typecheck
npm test
npm run build
node dist/cli/index.js scan test/fixtures/benign
```

Runtime dependencies stay at four: `commander`, `zod`, `yaml`, and `picomatch`. Do not add a package that compiles native code, and do not add install scripts.
