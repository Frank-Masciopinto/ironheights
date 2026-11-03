#!/usr/bin/env python3
"""Build bench/realworld/manifest.json (IDs + SHA-256 only, no skill text) and
bench/blind/manifest.json from locally downloaded, pinned upstream files.

Run by a maintainer only when the corpus is refreshed. CI never runs this; it runs
scripts/realworld-gate.py, which re-downloads the same pinned files and checks every hash.

usage: realworld-build-manifest.py <dir with signals *.jsonl, goku gNN.jsonl, skillmd.parquet, msb.parquet>

Selection (deterministic):
  ClawHub  - GokuScraper/clawhub-skills text, joined on owner/slug@version with
             OpenClaw/clawhub-security-signals; kept only when ClawScan (high confidence),
             static analysis, VirusTotal and NVIDIA SkillSpector all say clean.
             Top 3000 by downloads, plus the top 300 of each look-alike category
             (monitoring/daemon, backup, installer, scheduler, API key).
  GitHub   - FayeZC/SkillMD-138K files from repositories with >= 5000 stars, at most
             20 per repository.
  Blind    - 600 malicious + 300 benign MaliciousSkillBench rows that are NOT in
             bench/msb/manifest.json and share no structural family with it, chosen by
             SHA-256 of (salt, benchmark_id). Only IDs and hashes are written; text is never printed.
"""
import glob, hashlib, json, os, re, sys

src = sys.argv[1]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sha = lambda b: hashlib.sha256(b).hexdigest()

SIG_REV = '69dcbd323c155312fb000ec89ea0b1efdf6a5757'
GOKU_REV = '240122b936774532c3ec5df8610c72938a3ce751'
SKILLMD_REV = '0d73048abf2fb6ee91f6f9f5ac598d5be8d6bdd7'

CATS = {
    'monitoring': r'\b(monitor\w*|daemon|background|watchdog|uptime|heartbeat|nohup|systemd)\b',
    'backup': r'\b(backup|back up|snapshot|restore)\b',
    'installer': r'\b(install\.sh|curl [^\n|]*\|\s*(ba)?sh|pip install|npm install|brew install|apt(-get)? install)\b',
    'scheduler': r'\b(cron\w*|schedul\w*|launchd|every \d+ (min|hour))',
    'api-key': r'\b(api[_ ]?key|[A-Z]+_API_KEY|bearer token|access token)\b',
}

def cats(text):
    return sorted(k for k, rx in CATS.items() if re.search(rx, text, re.I))

sig = {}
for f in ('train', 'validation', 'test', 'eval_holdout'):
    for line in open(os.path.join(src, f + '.jsonl')):
        r = json.loads(line)
        sig[r['skill_slug']] = {k: r.get(k) for k in ('skill_version', 'clawscan_verdict', 'clawscan_confidence',
                                                     'static_status', 'virustotal_status', 'skillspector_status')}
pool = []
shards = []
for i, f in enumerate(sorted(glob.glob(os.path.join(src, 'g[0-9][0-9].jsonl'))), 1):
    raw = open(f, 'rb').read()
    shards.append({'file': f'shards/shard-{i:05d}.jsonl', 'sha256': sha(raw)})
    for line in raw.decode('utf-8').split('\n'):
        if not line.strip():
            continue
        g = json.loads(line)
        key = f"{g['ownerHandle']}/{g['slug']}"
        s = sig.get(key)
        text = g.get('description') or ''
        if not s or s['skill_version'] != g['latestVersion'] or not text.lstrip().startswith('---'):
            continue
        if (s['clawscan_verdict'], s.get('clawscan_confidence'), s['static_status'],
                s['virustotal_status'], s['skillspector_status']) != ('clean', 'high', 'clean', 'clean', 'clean'):
            continue
        pool.append(dict(id=f"clawhub:{key}@{g['latestVersion']}", shard=i, slug=g['slug'], owner=g['ownerHandle'],
                         downloads=g['stats'].get('downloads', 0), text=text))
pool.sort(key=lambda p: (-p['downloads'], p['id']))
chosen, seen = {}, set()
def take(p):
    h = sha(p['text'].encode('utf-8'))
    if p['id'] in chosen or h in seen:
        return False
    seen.add(h)
    chosen[p['id']] = dict(id=p['id'], source='clawhub', shard=p['shard'], owner=p['owner'], slug=p['slug'],
                           categories=cats(p['text']), sha256=h)
    return True
n = 0
for p in pool:
    if n >= 3000:
        break
    n += take(p)
for c in CATS:
    n = 0
    for p in pool:
        if n >= 300:
            break
        if c in cats(p['text']):
            n += take(p)

import pyarrow.parquet as pq
import pyarrow.compute as pc
t = pq.read_table(os.path.join(src, 'skillmd.parquet'), columns=['content_hash', 'repo', 'path', 'stars', 'content'],
                  filters=[('stars', '>=', 5000)]).to_pylist()
t = [r for r in t if (r['stars'] or 0) >= 5000 and (r['content'] or '').lstrip().startswith('---')]
t.sort(key=lambda r: (-r['stars'], r['repo'], r['path']))
per = {}
for r in t:
    if per.get(r['repo'], 0) >= 20:
        continue
    h = sha(r['content'].encode('utf-8'))
    if h in seen:
        continue
    seen.add(h)
    per[r['repo']] = per.get(r['repo'], 0) + 1
    i = f"github:{r['repo']}/{r['path']}"
    chosen[i] = dict(id=i, source='skillmd', content_hash=r['content_hash'], categories=cats(r['content']), sha256=h)

skills = sorted(chosen.values(), key=lambda s: s['id'])
manifest = {
    'note': 'Real-world benign skills. IDs and SHA-256 hashes only; scripts/realworld-gate.py downloads the text from the pinned sources below and checks every hash.',
    'sources': {
        'clawhub': {'repo': 'GokuScraper/clawhub-skills', 'revision': GOKU_REV, 'license': 'CC BY 4.0 (compilation); each skill keeps its ClawHub license', 'shards': shards},
        'signals': {'repo': 'OpenClaw/clawhub-security-signals', 'revision': SIG_REV, 'license': 'MIT', 'use': 'label filter only (all four scanners clean); not downloaded in CI'},
        'skillmd': {'repo': 'FayeZC/SkillMD-138K', 'revision': SKILLMD_REV, 'file': 'train.parquet',
                    'sha256': sha(open(os.path.join(src, 'skillmd.parquet'), 'rb').read()),
                    'license': 'CC BY 4.0 (compilation); each file keeps its GitHub repository license'},
    },
    'counts': {'total': len(skills), 'clawhub': sum(s['source'] == 'clawhub' for s in skills),
               'github': sum(s['source'] == 'skillmd' for s in skills),
               **{c: sum(c in s['categories'] for s in skills) for c in CATS}},
    'skills': skills,
}
json.dump(manifest, open(os.path.join(ROOT, 'bench/realworld/manifest.json'), 'w'), indent=0)
print(json.dumps(manifest['counts']))

# Blind held-out slice of MaliciousSkillBench. Never print or open this text when writing rules.
msb = json.load(open(os.path.join(ROOT, 'bench/msb/manifest.json')))
used = {s['id'] for s in msb['skills']}
t = pq.read_table(os.path.join(src, 'msb.parquet'), columns=['benchmark_id', 'label', 'skill_text', 'structural_family_id']).to_pylist()
used_fam = {r['structural_family_id'] for r in t if r['benchmark_id'] in used and r['structural_family_id']}
SALT = 'ironheights-blind-2026-11-02'
cand = [r for r in t if r['benchmark_id'] not in used and r['skill_text'] and r['structural_family_id'] not in used_fam]
cand.sort(key=lambda r: sha(f"{SALT}:{r['benchmark_id']}".encode()))
blind = []
for label, want in (('1', 600), ('0', 300)):
    blind += [dict(id=r['benchmark_id'], label='malicious' if label == '1' else 'benign',
                   sha256=sha(r['skill_text'].encode('utf-8'))) for r in cand if str(r['label']) == label][:want]
blind.sort(key=lambda s: s['id'])
os.makedirs(os.path.join(ROOT, 'bench/blind'), exist_ok=True)
json.dump({'note': 'BLIND HELD-OUT SET. Do not open, print, grep or read these skills when writing or tuning rules. '
                   'Only aggregate scores may be looked at. See docs/accuracy-gates.md.',
           'msb': msb['msb'], 'salt': SALT,
           'counts': {'malicious': sum(s['label'] == 'malicious' for s in blind), 'benign': sum(s['label'] == 'benign' for s in blind)},
           'skills': blind}, open(os.path.join(ROOT, 'bench/blind/manifest.json'), 'w'), indent=0)
print('blind', len(blind))
