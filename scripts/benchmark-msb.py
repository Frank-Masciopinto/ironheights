#!/usr/bin/env python3
"""Score the built CLI on MaliciousSkillBench and write a shields.io endpoint JSON.

usage: benchmark-msb.py <cli.js> <out-dir> [<cisco skill-scanner binary>]

With the third argument it also runs Cisco skill-scanner (pinned in
bench/msb/requirements-cisco.txt, static analyzers only, no LLM/API key) on the
same corpus, scored the way docs/benchmark.md does: HIGH or CRITICAL = block, and
MEDIUM or above = "blocked or sent to review" (Cisco has no review verdict, so a MEDIUM
finding is treated as its review tier; LOW and INFO are advisory). It also scores both
scanners on the blind held-out set (bench/blind/manifest.json, aggregate counts only).
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

B = json.load(open(os.path.join(ROOT, 'bench/blind/manifest.json')))
if B['msb'] != {k: msb[k] for k in B['msb']}:
    sys.exit('blind manifest pins a different MaliciousSkillBench file')
for sk in B['skills']:
    body = texts[sk['id']].encode('utf-8')
    if sha(body) != sk['sha256']:
        sys.exit('hash mismatch in blind set')
    d = os.path.join(work, 'blind', sk['label'], sk['id'])
    os.makedirs(d)
    open(os.path.join(d, 'SKILL.md'), 'wb').write(body)
SETS = [('corpus', 'malicious'), ('corpus', 'benign'), ('blind', 'malicious'), ('blind', 'benign')]

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
for top, label in SETS:
    p = subprocess.run(['node', cli, 'scan', '--json', '--allow-skipped', os.path.join(work, top, label)],
                       capture_output=True, text=True)
    if not p.stdout.strip():
        sys.exit(f'scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}')
    for s in json.loads(p.stdout)['skills']:
        verdict[os.path.basename(os.path.realpath(s['root']))] = s['verdict']

missing = [s['id'] for s in M['skills'] + B['skills'] if s['id'] not in verdict]
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
bmal = [s for s in B['skills'] if s['label'] == 'malicious']
bben = [s for s in B['skills'] if s['label'] == 'benign']
if (len(bmal), len(bben)) != (600, 300):
    sys.exit('unexpected blind set size')
def frac(v, sub):
    h = sum(v[s['id']] for s in sub)
    return h, f'{round(100 * h / len(sub), 1)}% ({h}/{len(sub)})'
prose = [s for s in mal if s.get('kind') == 'prose']
if len(prose) != 98:
    sys.exit('unexpected prose-only attack count')
def extra(block, review):
    # rows beyond the main three: block-or-review on the main set, block on the blind set,
    # and the prose-only (plain-language) attacks, tagged `kind: prose` in bench/msb/manifest.json
    return dict(review_detect=frac(review, mal), review_fp=frac(review, ben),
                blind_detect=frac(block, bmal), blind_fp=frac(block, bben),
                prose_detect=frac(block, prose), prose_review=frac(review, prose))
ih = score({k: v == 'block' for k, v in verdict.items()})
ihx = extra({k: v == 'block' for k, v in verdict.items()}, {k: v in ('block', 'review') for k, v in verdict.items()})
version = json.load(open(os.path.join(ROOT, 'package.json')))['version']
os.makedirs(out_dir, exist_ok=True)
summary = dict(version=version, **{k: v for k, v in ih.items() if not k.startswith('_')},
               **{k: v[1] for k, v in ihx.items()},
               msb_revision=msb['revision'], anthropic_commit=M['anthropic']['commit'])

def endpoint(name, message, win):
    json.dump(dict(schemaVersion=1, label='', message=message + (' ✅' if win else ''),
                   color='brightgreen' if win else 'lightgrey', style='for-the-badge'),
              open(os.path.join(out_dir, name), 'w'), ensure_ascii=False)

if cisco:
    cs, csr, cs_sev = {}, {}, {}
    for top, label in SETS:
        rep = os.path.join(work, f'cisco-{top}-{label}.json')
        p = subprocess.run([cisco, 'scan-all', os.path.join(work, top, label), '--format', 'json',
                            '--output', rep], capture_output=True, text=True)
        if not os.path.exists(rep):
            sys.exit(f'cisco scan produced no report (exit {p.returncode}): {p.stderr[-2000:]}')
        for r in json.load(open(rep))['results']:
            k = os.path.basename(os.path.realpath(r['skill_path']))
            cs_sev[k] = r['max_severity']
            cs[k] = r['max_severity'] in ('HIGH', 'CRITICAL')
            csr[k] = r['max_severity'] in ('MEDIUM', 'HIGH', 'CRITICAL')
    missing = [s['id'] for s in M['skills'] + B['skills'] if s['id'] not in cs]
    if missing:
        sys.exit(f'{len(missing)} skills missing from cisco output')
    ver = subprocess.run([cisco, '--version'], capture_output=True, text=True, check=True).stdout.split()[-1]
    c = score(cs)
    cx = extra(cs, csr)
    summary['cisco'] = dict(version=ver, **{k: v for k, v in c.items() if not k.startswith('_')},
                            **{k: v[1] for k, v in cx.items()})
    for k, higher in (('review_detect', True), ('review_fp', False), ('blind_detect', True), ('blind_fp', False)):
        a, b = ihx[k][0], cx[k][0]
        endpoint(f"table-ih-{k.replace('_', '-')}.json", ihx[k][1], a > b if higher else a < b)
        endpoint(f"table-cisco-{k.replace('_', '-')}.json", cx[k][1], b > a if higher else b < a)
    endpoint('table-ih-detect.json', f"{ih['detect_pct']}% ({ih['detect']})", ih['_tp'] > c['_tp'])
    endpoint('table-cisco-detect.json', f"{c['detect_pct']}% ({c['detect']})", c['_tp'] > ih['_tp'])
    endpoint('table-ih-fp.json', f"{ih['fp_pct']}% ({ih['fp']})", ih['_fp'] < c['_fp'])
    endpoint('table-cisco-fp.json', f"{c['fp_pct']}% ({c['fp']})", c['_fp'] < ih['_fp'])
    endpoint('table-ih-anthropic.json', ih['anthropic'], ih['_an'] < c['_an'])
    endpoint('table-cisco-anthropic.json', c['anthropic'], c['_an'] < ih['_an'])

# Proof files: per-skill verdicts for the public set, aggregate-only digest for the blind set
# (blind ids and per-skill verdicts are never published, so nobody can tune rules against them).
import csv, datetime
sha_c = os.environ.get('GITHUB_SHA') or subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
run_url = (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
           if os.environ.get('GITHUB_RUN_ID') else 'local run')
cver = summary.get('cisco', {}).get('version', '')
with open(os.path.join(out_dir, 'results.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['row_id', 'label', 'scanner', 'scanner_version', 'verdict', 'counted_block', 'counted_block_or_review', 'timestamp_utc', 'commit_sha'])
    for s_ in M['skills']:
        v = verdict[s_['id']]
        w.writerow([s_['id'], s_['label'], 'ironheights', version, v, v == 'block', v in ('block', 'review'), stamp, sha_c])
        if cisco:
            w.writerow([s_['id'], s_['label'], 'cisco-skill-scanner', cver, cs_sev[s_['id']], cs[s_['id']], csr[s_['id']], stamp, sha_c])
def digest(fn):
    rows = sorted(f"{s_['id']}:{fn(s_['id'])}" for s_ in B['skills'])
    return hashlib.sha256('\n'.join(rows).encode()).hexdigest()
blind = dict(note='Aggregate only. sha256 is over sorted "id:verdict" lines; rerun the script to reproduce it.',
             ironheights=dict(version=version, detect=ihx['blind_detect'][1], fp=ihx['blind_fp'][1],
                              sha256=digest(lambda i: verdict[i])))
if cisco:
    blind['cisco'] = dict(version=cver, detect=cx['blind_detect'][1], fp=cx['blind_fp'][1], sha256=digest(lambda i: cs_sev[i]))
json.dump(blind, open(os.path.join(out_dir, 'blind-aggregate.json'), 'w'), indent=1)
summary.update(run_url=run_url, commit_sha=sha_c, timestamp_utc=stamp)
open(os.path.join(out_dir, 'PROOF.md'), 'w').write(f"""# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: {run_url}
- Commit: `{sha_c}`
- Time (UTC): {stamp}
- Ironheights {version}; Cisco skill-scanner {cver or 'not run'} (static analyzers only, no LLM)
- MaliciousSkillBench revision `{msb['revision']}`

| Row | Ironheights | Cisco |
|---|---|---|
| Malicious detected (block) | {ih['detect']} | {summary.get('cisco', {}).get('detect', '')} |
| Clean false positives (block) | {ih['fp']} | {summary.get('cisco', {}).get('fp', '')} |
| Malicious block or review | {ihx['review_detect'][1]} | {summary.get('cisco', {}).get('review_detect', '')} |
| Clean block or review | {ihx['review_fp'][1]} | {summary.get('cisco', {}).get('review_fp', '')} |
| Blind attacks blocked | {ihx['blind_detect'][1]} | {summary.get('cisco', {}).get('blind_detect', '')} |
| Blind clean blocked | {ihx['blind_fp'][1]} | {summary.get('cisco', {}).get('blind_fp', '')} |
| Prose-only attacks blocked | {ihx['prose_detect'][1]} | {summary.get('cisco', {}).get('prose_detect', '')} |
| Prose-only attacks block or review | {ihx['prose_review'][1]} | {summary.get('cisco', {}).get('prose_review', '')} |
| Anthropic skills flagged | {ih['anthropic']} | {summary.get('cisco', {}).get('anthropic', '')} |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
""")
json.dump(summary, open(os.path.join(out_dir, 'benchmark-summary.json'), 'w'), indent=1)
json.dump(dict(schemaVersion=1, label='MaliciousSkillBench',
               message=f"{ih['detect_pct']:.1f}% detect · {ih['fp_pct']:.1f}% FP", color='blue'),
          open(os.path.join(out_dir, 'benchmark.json'), 'w'), ensure_ascii=False)
print(json.dumps(summary))
