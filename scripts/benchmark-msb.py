#!/usr/bin/env python3
"""Score the built CLI on MaliciousSkillBench and write a shields.io endpoint JSON.

usage: benchmark-msb.py <cli.js> <out-dir>

Fetches skill text from pinned upstream sources (hash-checked), writes it to a temp
dir, runs `scan --json` (nothing is executed), and scores block-only verdicts.
Exits non-zero on any mismatch, so the caller never publishes a bad number.
"""
import hashlib, json, os, subprocess, sys, tempfile, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = json.load(open(os.path.join(ROOT, 'bench/msb/manifest.json')))
cli, out_dir = sys.argv[1], sys.argv[2]

def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()

def sha(b):
    return hashlib.sha256(b).hexdigest()

work = tempfile.mkdtemp(prefix='msb-')
msb = M['msb']
pq = fetch(f"https://huggingface.co/datasets/{msb['repo']}/resolve/{msb['revision']}/{msb['file']}")
if sha(pq) != msb['sha256']:
    sys.exit('primary.parquet hash mismatch')
open(os.path.join(work, 'primary.parquet'), 'wb').write(pq)
import pyarrow.parquet as papq
t = papq.read_table(os.path.join(work, 'primary.parquet'), columns=['benchmark_id', 'skill_text']).to_pydict()
texts = {i: s for i, s in zip(t['benchmark_id'], t['skill_text']) if s is not None}

for sk in M['skills']:
    if sk['id'].startswith('anthropic_'):
        name = sk['id'][len('anthropic_'):]
        body = fetch(f"https://raw.githubusercontent.com/{M['anthropic']['repo']}/{M['anthropic']['commit']}/skills/{name}/SKILL.md")
    else:
        body = texts[sk['id']].encode('utf-8')
    if sha(body) != sk['sha256']:
        sys.exit(f"hash mismatch for {sk['id']}")
    d = os.path.join(work, 'corpus', sk['label'], sk['id'])
    os.makedirs(d)
    open(os.path.join(d, 'SKILL.md'), 'wb').write(body)

verdict = {}
for label in ('malicious', 'benign'):
    p = subprocess.run(['node', cli, 'scan', '--json', '--allow-skipped', os.path.join(work, 'corpus', label)],
                       capture_output=True, text=True)
    for s in json.loads(p.stdout)['skills']:
        verdict[os.path.basename(os.path.realpath(s['root']))] = s['verdict']

missing = [s['id'] for s in M['skills'] if s['id'] not in verdict]
if missing:
    sys.exit(f'{len(missing)} skills missing from scan output')
mal = [s for s in M['skills'] if s['label'] == 'malicious']
ben = [s for s in M['skills'] if s['label'] == 'benign']
if (len(mal), len(ben)) != (516, 456):
    sys.exit('unexpected corpus size')
tp = sum(verdict[s['id']] == 'block' for s in mal)
fp = sum(verdict[s['id']] == 'block' for s in ben)
det, fpr = 100 * tp / len(mal), 100 * fp / len(ben)
version = json.load(open(os.path.join(ROOT, 'package.json')))['version']
os.makedirs(out_dir, exist_ok=True)
summary = dict(version=version, detect=f'{tp}/{len(mal)}', fp=f'{fp}/{len(ben)}',
               detect_pct=round(det, 1), fp_pct=round(fpr, 1),
               msb_revision=msb['revision'], anthropic_commit=M['anthropic']['commit'])
json.dump(summary, open(os.path.join(out_dir, 'benchmark-summary.json'), 'w'), indent=1)
json.dump(dict(schemaVersion=1, label='MaliciousSkillBench',
               message=f'{det:.1f}% detect · {fpr:.1f}% FP', color='blue'),
          open(os.path.join(out_dir, 'benchmark.json'), 'w'), ensure_ascii=False)
print(json.dumps(summary))
