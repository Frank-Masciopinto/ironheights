#!/usr/bin/env python3
"""Score the built CLI on MaliciousSkillBench and write a shields.io endpoint JSON.

usage: benchmark-msb.py <cli.js> <out-dir> [<cisco skill-scanner binary>]

With the third argument it also runs Cisco skill-scanner (pinned in
bench/msb/requirements-cisco.txt, static analyzers only, no LLM/API key) on the
same corpus, scored the way docs/benchmark.md does: HIGH or CRITICAL = block.
It then writes one shields.io endpoint file per cell of the README comparison table.

Fetches skill text from pinned upstream sources (hash-checked), writes it to a temp
dir, runs `scan --json` (nothing is executed), and scores block-only verdicts.
Exits non-zero on any mismatch, so the caller never publishes a bad number.
"""
import hashlib, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = json.load(open(os.path.join(ROOT, 'bench/msb/manifest.json')))
cli, out_dir = sys.argv[1], sys.argv[2]
cisco = sys.argv[3] if len(sys.argv) > 3 else None

def fetch(url, tries=5):
    # Retry only transient errors (network, timeout, 429, 5xx). Content is pinned and
    # hash-checked, so a retry can never change the result.
    for n in range(1, tries + 1):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500 or n == tries:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if n == tries:
                raise
        print(f'transient error fetching {url}, retry {n}/{tries - 1}', file=sys.stderr)
        time.sleep(5 * 2 ** (n - 1))

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
    if not p.stdout.strip():
        sys.exit(f'scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}')
    for s in json.loads(p.stdout)['skills']:
        verdict[os.path.basename(os.path.realpath(s['root']))] = s['verdict']

missing = [s['id'] for s in M['skills'] if s['id'] not in verdict]
if missing:
    sys.exit(f'{len(missing)} skills missing from scan output')
mal = [s for s in M['skills'] if s['label'] == 'malicious']
ben = [s for s in M['skills'] if s['label'] == 'benign']
if (len(mal), len(ben)) != (516, 456):
    sys.exit('unexpected corpus size')
anth = [s for s in ben if s['id'].startswith('anthropic_')]
if len(anth) != 19:
    sys.exit('unexpected Anthropic skill count')
def score(v):
    tp = sum(v[s['id']] for s in mal)
    fp = sum(v[s['id']] for s in ben)
    an = sum(v[s['id']] for s in anth)
    return dict(detect=f'{tp}/{len(mal)}', fp=f'{fp}/{len(ben)}', anthropic=f'{an}/{len(anth)}',
                detect_pct=round(100 * tp / len(mal), 1), fp_pct=round(100 * fp / len(ben), 1),
                _tp=tp, _fp=fp, _an=an)
ih = score({k: v == 'block' for k, v in verdict.items()})
version = json.load(open(os.path.join(ROOT, 'package.json')))['version']
os.makedirs(out_dir, exist_ok=True)
summary = dict(version=version, **{k: v for k, v in ih.items() if not k.startswith('_')},
               msb_revision=msb['revision'], anthropic_commit=M['anthropic']['commit'])

def endpoint(name, message, win):
    json.dump(dict(schemaVersion=1, label='', message=message + (' ✅' if win else ''),
                   color='brightgreen' if win else 'lightgrey', style='for-the-badge'),
              open(os.path.join(out_dir, name), 'w'), ensure_ascii=False)

if cisco:
    cs = {}
    for label in ('malicious', 'benign'):
        rep = os.path.join(work, f'cisco-{label}.json')
        p = subprocess.run([cisco, 'scan-all', os.path.join(work, 'corpus', label), '--format', 'json',
                            '--output', rep], capture_output=True, text=True)
        if not os.path.exists(rep):
            sys.exit(f'cisco scan produced no report (exit {p.returncode}): {p.stderr[-2000:]}')
        for r in json.load(open(rep))['results']:
            cs[os.path.basename(os.path.realpath(r['skill_path']))] = r['max_severity'] in ('HIGH', 'CRITICAL')
    missing = [s['id'] for s in M['skills'] if s['id'] not in cs]
    if missing:
        sys.exit(f'{len(missing)} skills missing from cisco output')
    ver = subprocess.run([cisco, '--version'], capture_output=True, text=True, check=True).stdout.split()[-1]
    c = score(cs)
    summary['cisco'] = dict(version=ver, **{k: v for k, v in c.items() if not k.startswith('_')})
    endpoint('table-ih-detect.json', f"{ih['detect_pct']}% ({ih['detect']})", ih['_tp'] > c['_tp'])
    endpoint('table-cisco-detect.json', f"{c['detect_pct']}% ({c['detect']})", c['_tp'] > ih['_tp'])
    endpoint('table-ih-fp.json', f"{ih['fp_pct']}% ({ih['fp']})", ih['_fp'] < c['_fp'])
    endpoint('table-cisco-fp.json', f"{c['fp_pct']}% ({c['fp']})", c['_fp'] < ih['_fp'])
    endpoint('table-ih-anthropic.json', ih['anthropic'], ih['_an'] < c['_an'])
    endpoint('table-cisco-anthropic.json', c['anthropic'], c['_an'] < ih['_an'])

json.dump(summary, open(os.path.join(out_dir, 'benchmark-summary.json'), 'w'), indent=1)
json.dump(dict(schemaVersion=1, label='MaliciousSkillBench',
               message=f"{ih['detect_pct']:.1f}% detect · {ih['fp_pct']:.1f}% FP", color='blue'),
          open(os.path.join(out_dir, 'benchmark.json'), 'w'), ensure_ascii=False)
print(json.dumps(summary))
