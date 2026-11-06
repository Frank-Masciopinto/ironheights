#!/usr/bin/env python3
"""Accuracy gates run on every PR (see docs/accuracy-gates.md).

usage: realworld-gate.py <cli.js> <out-dir> [--write-baseline]

1. Real-world clean set (bench/realworld/manifest.json, 5,000+ real ClawHub and GitHub skills).
   Fails if any skill is blocked that is not listed in bench/realworld/baseline.json, so a PR
   can never add a false positive on real skills without a reviewed baseline change.
   Shadow-mode checks are scanned with IRONHEIGHTS_SHADOW=enforce as well and reported as
   "would block"; a shadow check may only be promoted when that list is empty.
2. Blind held-out attack set (bench/blind/manifest.json). Prints aggregate counts only, never
   skill text, IDs or evidence. Fails if detection drops below the baseline or FPs rise.

Downloads come from pinned revisions and every file and skill is SHA-256 checked. Only
transient network errors are retried. Set IH_GATE_CACHE to reuse downloads.
"""
import hashlib, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cli, out_dir = sys.argv[1], sys.argv[2]
write_baseline = '--write-baseline' in sys.argv
RW = json.load(open(os.path.join(ROOT, 'bench/realworld/manifest.json')))
BL = json.load(open(os.path.join(ROOT, 'bench/blind/manifest.json')))
BASE_PATH = os.path.join(ROOT, 'bench/realworld/baseline.json')
cache = os.path.expanduser(os.environ.get('IH_GATE_CACHE') or '') or tempfile.mkdtemp(prefix='ih-gate-cache-')
os.makedirs(cache, exist_ok=True)
sha = lambda b: hashlib.sha256(b).hexdigest()

def fetch(url, want, name, tries=5):
    path = os.path.join(cache, name)
    if os.path.exists(path):
        data = open(path, 'rb').read()
        if sha(data) == want:
            return data
    for n in range(1, tries + 1):
        try:
            with urllib.request.urlopen(url, timeout=300) as r:
                data = r.read()
            break
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500 or n == tries:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if n == tries:
                raise
        print(f'transient error fetching {name}, retry {n}/{tries - 1}', file=sys.stderr)
        time.sleep(5 * 2 ** (n - 1))
    if sha(data) != want:
        sys.exit(f'hash mismatch for {name}')
    open(path, 'wb').write(data)
    return data

work = tempfile.mkdtemp(prefix='ih-gate-')
import pyarrow.parquet as pq

# --- real-world corpus
src = RW['sources']
texts = {}
need_shards = {s['shard'] for s in RW['skills'] if s['source'] == 'clawhub'}
for i, shard in enumerate(src['clawhub']['shards'], 1):
    if i not in need_shards:
        continue
    raw = fetch(f"https://huggingface.co/datasets/{src['clawhub']['repo']}/resolve/{src['clawhub']['revision']}/{shard['file']}",
                shard['sha256'], f'clawhub-{i:05d}.jsonl')
    for line in raw.decode('utf-8').split('\n'):
        if line.strip():
            g = json.loads(line)
            texts[(i, g['ownerHandle'], g['slug'])] = g.get('description') or ''
    del raw
sm = src['skillmd']
p = os.path.join(cache, 'skillmd.parquet')
fetch(f"https://huggingface.co/datasets/{sm['repo']}/resolve/{sm['revision']}/{sm['file']}", sm['sha256'], 'skillmd.parquet')
want = {s['content_hash'] for s in RW['skills'] if s['source'] == 'skillmd'}
t = pq.read_table(p, columns=['content_hash', 'content'], filters=[('content_hash', 'in', list(want))]).to_pydict()
gh = dict(zip(t['content_hash'], t['content']))

def safe(i):
    return hashlib.sha256(i.encode()).hexdigest()[:20]
rw_dir = os.path.join(work, 'realworld')
names = {}
for s in RW['skills']:
    body = (texts.get((s['shard'], s['owner'], s['slug'])) if s['source'] == 'clawhub' else gh.get(s['content_hash']))
    if body is None or sha(body.encode('utf-8')) != s['sha256']:
        sys.exit(f"hash mismatch for {s['id']}")
    d = os.path.join(rw_dir, safe(s['id']))
    os.makedirs(d)
    open(os.path.join(d, 'SKILL.md'), 'wb').write(body.encode('utf-8'))
    names[safe(s['id'])] = s['id']
del texts, gh

def scan(path, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    p = subprocess.run(['node', cli, 'scan', '--json', '--allow-skipped', path], capture_output=True, text=True, env=env)
    if not p.stdout.strip():
        sys.exit(f'scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}')
    res = {}
    for sk in json.loads(p.stdout)['skills']:
        rules = sorted({f['ruleId'] for f in sk['findings'] if f.get('ruleId')})
        crit = sorted({f['ruleId'] for f in sk['findings'] if f['severity'] == 'critical'})
        if sk['verdict'] == 'review':
            crit = [r for r in rules if r in {f['ruleId'] for f in sk['findings'] if f['severity'] in ('critical', 'high')}] or ['score']
        else:
            crit = crit or ['score']
        res[os.path.basename(os.path.realpath(sk['root']))] = (sk['verdict'], crit, rules)
    return res

def rule_counts(res):
    counts = {}
    for verdict, _crit, rules in res.values():
        for rule_id in rules:
            counts.setdefault(rule_id, {'skills': 0, 'block': 0, 'review': 0})
            counts[rule_id]['skills'] += 1
            if verdict == 'block':
                counts[rule_id]['block'] += 1
            elif verdict == 'review':
                counts[rule_id]['review'] += 1
    return {k: counts[k] for k in sorted(counts)}

def blocked(res):
    return {names[k]: v[1] for k, v in res.items() if v[0] == 'block'}

def reviewed(res):
    return {names[k]: v[1] for k, v in res.items() if v[0] == 'review'}

live = scan(rw_dir)
if len(live) != len(RW['skills']):
    sys.exit(f'{len(RW["skills"]) - len(live)} real-world skills missing from scan output')
now = blocked(live)
rev = reviewed(live)
enforced = scan(rw_dir, {'IRONHEIGHTS_SHADOW': 'enforce'})
would = {k: v for k, v in blocked(enforced).items() if k not in now}
would_rev = {k: v for k, v in reviewed(enforced).items() if k not in rev and k not in now}

# --- blind held-out attacks (aggregate only)
msb = BL['msb']
fetch(f"https://huggingface.co/datasets/{msb['repo']}/resolve/{msb['revision']}/{msb['file']}", msb['sha256'], 'msb.parquet')
ids = {s['id'] for s in BL['skills']}
t = pq.read_table(os.path.join(cache, 'msb.parquet'), columns=['benchmark_id', 'skill_text']).to_pydict()
bt = {i: x for i, x in zip(t['benchmark_id'], t['skill_text']) if i in ids}
del t
bl_dir = os.path.join(work, 'blind')
for s in BL['skills']:
    body = (bt.get(s['id']) or '').encode('utf-8')
    if sha(body) != s['sha256']:
        sys.exit('blind set hash mismatch')  # never name the skill
    d = os.path.join(bl_dir, s['label'], safe(s['id']))
    os.makedirs(d)
    open(os.path.join(d, 'SKILL.md'), 'wb').write(body)
del bt
blind = {}
for label in ('malicious', 'benign'):
    r = scan(os.path.join(bl_dir, label))
    if len(r) != BL['counts'][label]:
        sys.exit('blind set skills missing from scan output')
    blind[label] = sum(v[0] == 'block' for v in r.values())

by_rule = {}
for rules in now.values():
    for r in rules:
        by_rule[r] = by_rule.get(r, 0) + 1
version = json.load(open(os.path.join(ROOT, 'package.json')))['version']
report = dict(version=version, realworld_total=len(RW['skills']), realworld_blocked=len(now),
              realworld_blocked_by_rule=dict(sorted(by_rule.items())),
              realworld_review=len(rev),
              shadow_would_block=len(would),
              shadow_would_review=len(would_rev),
              rule_counts=rule_counts(live),
              enforce_rule_counts=rule_counts(enforced),
              blind=dict(detect=f"{blind['malicious']}/{BL['counts']['malicious']}", fp=f"{blind['benign']}/{BL['counts']['benign']}"))
os.makedirs(out_dir, exist_ok=True)
json.dump(dict(report, blocked=now, review=rev, shadow_would_block_ids=would, shadow_would_review_ids=would_rev), open(os.path.join(out_dir, 'realworld-gate.json'), 'w'), indent=1)
print(json.dumps(report, indent=1))

if write_baseline:
    json.dump({'note': 'Real-world skills main currently blocks or sends to review (reviewed). The PR gate fails on any block or review not listed here. '
                       'Shrink this list freely; growing it needs an explicit reviewed reason in the PR.',
               'version': version, 'blind': dict(malicious=blind['malicious'], benign=blind['benign']),
               'blocked': {k: now[k] for k in sorted(now)},
               'review': {k: rev[k] for k in sorted(rev)}}, open(BASE_PATH, 'w'), indent=1)
    print('baseline written')
    sys.exit(0)

base = json.load(open(BASE_PATH))
new = sorted(k for k in now if k not in base['blocked'])
fixed = sorted(k for k in base['blocked'] if k not in now)
base_rev = base.get('review', {})
# A skill main already blocks or sends to review is not new; a block that drops to review is not new.
new_rev = sorted(k for k in rev if k not in base_rev and k not in base['blocked'])
fail = []
lines = [f"## Accuracy gates ({version})", '',
         f"| Gate | Baseline (main) | This PR | Result |", '|---|---|---|---|',
         f"| Real-world clean skills blocked | {len(base['blocked'])}/{len(RW['skills'])} | {len(now)}/{len(RW['skills'])} | {'FAIL: ' + str(len(new)) + ' new' if new else 'pass'} |",
         f"| Real-world clean skills sent to review | {len(base_rev)}/{len(RW['skills'])} | {len(rev)}/{len(RW['skills'])} | {'FAIL: ' + str(len(new_rev)) + ' new' if new_rev else 'pass'} |",
         f"| Blind attacks blocked | {base['blind']['malicious']}/{BL['counts']['malicious']} | {blind['malicious']}/{BL['counts']['malicious']} | {'FAIL' if blind['malicious'] < base['blind']['malicious'] else 'pass'} |",
         f"| Blind benign blocked | {base['blind']['benign']}/{BL['counts']['benign']} | {blind['benign']}/{BL['counts']['benign']} | {'FAIL' if blind['benign'] > base['blind']['benign'] else 'pass'} |",
         f"| Shadow checks would block (real-world) | - | {len(would)} | {'not promotable' if would else 'promotable'} |",
         f"| Shadow checks would send to review (real-world) | - | {len(would_rev)} | {'review hits' if would_rev else 'none'} |", '']
if new:
    fail.append('new real-world blocks')
    lines += ['New real-world blocks (each is a likely false positive):', ''] + [f"- `{k}` ({', '.join(now[k])})" for k in new] + ['']
if new_rev:
    fail.append('new real-world review verdicts')
    lines += ['New real-world review verdicts (each is a likely false positive):', ''] + [f"- `{k}` ({', '.join(rev[k])})" for k in new_rev] + ['']
if fixed:
    lines += [f"{len(fixed)} baseline blocks no longer block (run with --write-baseline to shrink the baseline)."]
if blind['malicious'] < base['blind']['malicious']:
    fail.append('blind detection dropped')
if blind['benign'] > base['blind']['benign']:
    fail.append('blind false positives rose')
summary = '\n'.join(lines)
print(summary)
if os.environ.get('GITHUB_STEP_SUMMARY'):
    open(os.environ['GITHUB_STEP_SUMMARY'], 'a').write(summary + '\n')
if fail:
    sys.exit('accuracy gate failed: ' + ', '.join(fail))
