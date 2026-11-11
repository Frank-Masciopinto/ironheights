#!/usr/bin/env python3
"""Score the built CLI on MaliciousSkillBench and write a shields.io endpoint JSON.

usage: benchmark-msb.py <cli.js> <out-dir> [<cisco skill-scanner>] [<skillspector>]

With the third argument it also runs Cisco skill-scanner (pinned in
bench/msb/requirements-cisco.txt, static analyzers only, no LLM/API key) on the
same corpus, scored the way docs/benchmark.md does: HIGH or CRITICAL = block, and
MEDIUM or above = "blocked or sent to review" (Cisco has no review verdict, so a MEDIUM
finding is treated as its review tier; LOW and INFO are advisory).

With the fourth argument it also runs NVIDIA SkillSpector at the commit pinned in
bench/msb/requirements-nvidia.txt. Each sample is `skillspector scan <skill-dir>
--no-llm --format json` (static analyzers only, no API key). Block is critical/high
severity or recommendation DO_NOT_INSTALL. Block-or-review also counts medium
severity or recommendation CAUTION. See docs/benchmark.md.

It also scores every scanner that was passed on the blind held-out set
(bench/blind/manifest.json, aggregate counts only). It then writes one shields.io
endpoint file per cell of the README comparison table. The green check goes to the
unique best value on that row. A tie gets no check.

Fetches skill text from pinned upstream sources (hash-checked), writes it to a temp
dir, runs `scan --json` (nothing is executed), and scores block-only verdicts.
Exits non-zero on any mismatch, so the caller never publishes a bad number.
"""
import csv, datetime, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.error, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = json.load(open(os.path.join(ROOT, 'bench/msb/manifest.json')))
cli, out_dir = sys.argv[1], sys.argv[2]
cisco = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
nvidia = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else None

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

def pinned_nvidia_commit():
    text = open(os.path.join(ROOT, 'bench/msb/requirements-nvidia.txt')).read()
    found = re.search(r'SkillSpector\.git@([0-9a-f]{40})', text)
    if not found:
        sys.exit('bench/msb/requirements-nvidia.txt has no pinned SkillSpector commit')
    return found.group(1)

def installed_nvidia_commit(binary):
    shebang = open(binary).readline().strip()
    if not shebang.startswith('#!'):
        sys.exit(f'{binary} has no Python shebang, so its install commit cannot be checked')
    py = shebang[2:].strip().split()[0]
    # abspath, not realpath: the venv python is often a symlink to /usr/bin/python3.
    root = os.path.dirname(os.path.dirname(os.path.abspath(py)))
    commits = set()
    found = False
    for dirpath, dirnames, filenames in os.walk(root):
        if 'direct_url.json' not in filenames or not os.path.basename(dirpath).startswith('skillspector-'):
            continue
        found = True
        info = json.load(open(os.path.join(dirpath, 'direct_url.json')))
        commit = (info.get('vcs_info') or {}).get('commit_id') or ''
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            sys.exit(f'{dirpath}/direct_url.json has no commit_id')
        commits.add(commit)
    if not found or len(commits) != 1:
        sys.exit(f'expected one SkillSpector commit under {root}, found {sorted(commits)}')
    return commits.pop()

# SkillSpector risk_assessment (nodes/report.py at the pinned commit):
# score >= 81 CRITICAL, >= 51 HIGH, >= 21 MEDIUM, else LOW.
# recommendation is SAFE, CAUTION, or DO_NOT_INSTALL.
# max_issue_severity is the worst finding and can be HIGH while the score band is LOW.
NV_BLOCK_SEVERITY = {'HIGH', 'CRITICAL'}
NV_REVIEW_SEVERITY = {'MEDIUM', 'HIGH', 'CRITICAL'}

def nvidia_flags(report):
    ra = report.get('risk_assessment') or {}
    severity = str(ra.get('severity') or '').upper()
    worst = str(ra.get('max_issue_severity') or '').upper()
    recommendation = str(ra.get('recommendation') or '').upper()
    if not severity or not recommendation:
        return None
    blocked = severity in NV_BLOCK_SEVERITY or worst in NV_BLOCK_SEVERITY or recommendation == 'DO_NOT_INSTALL'
    review = blocked or severity in NV_REVIEW_SEVERITY or worst in NV_REVIEW_SEVERITY or recommendation == 'CAUTION'
    verdict = f'{severity}|{worst}|{recommendation}|score={ra.get("score")}'
    failed = report.get('execution_successful') is False
    return dict(blocked=False if failed else blocked, review=False if failed else review,
                verdict=verdict, failed=failed)

def _link_tree(src, dest):
    os.makedirs(dest, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        target = dest if rel == '.' else os.path.join(dest, rel)
        os.makedirs(target, exist_ok=True)
        for name in filenames:
            src_file = os.path.join(dirpath, name)
            dest_file = os.path.join(target, name)
            try:
                os.link(src_file, dest_file)
            except OSError:
                shutil.copy2(src_file, dest_file)

def _nvidia_entries(data):
    if data.get('multi_skill'):
        if data.get('skills_omitted') or data.get('skills_output_omitted'):
            return None
        entries = {}
        for entry in data.get('skills') or []:
            if entry.get('omitted') or entry.get('error') or not entry.get('risk_assessment'):
                return None
            sid = os.path.basename(str(entry.get('path') or '').rstrip('/'))
            if not sid or sid in entries:
                return None
            entries[sid] = entry
        return entries
    if not data.get('risk_assessment'):
        return None
    return {'.': data}

def scan_nvidia_batch(binary, batch):
    """Scan one skill directory, or a hardlinked batch, with static SkillSpector.

    Exit 1 means the tool found risk above its threshold. That report still counts.
    A missing report, exit 2, or an omitted skill returns None so the caller can split.
    """
    tmp = tempfile.mkdtemp(prefix='nvb-')
    try:
        if len(batch) == 1:
            target = batch[0]
            expected = [os.path.basename(batch[0])]
        else:
            target = os.path.join(tmp, 'skills')
            os.makedirs(target)
            expected = []
            for src in batch:
                sid = os.path.basename(src)
                expected.append(sid)
                _link_tree(src, os.path.join(target, sid))
        report_path = os.path.join(tmp, 'report.json')
        try:
            proc = subprocess.run(
                [binary, 'scan', target, '--no-llm', '--format', 'json', '--output', report_path]
                + ([] if len(batch) == 1 else ['--recursive', '--max-skills', str(len(batch))]),
                capture_output=True, text=True, timeout=120 if len(batch) == 1 else 240)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode not in (0, 1) or not os.path.exists(report_path):
            return None
        try:
            data = json.load(open(report_path))
        except json.JSONDecodeError:
            return None
        entries = _nvidia_entries(data)
        if entries is None:
            return None
        if len(batch) == 1:
            entries = {expected[0]: data}
        if set(entries) != set(expected):
            return None
        parsed = {}
        for sid, entry in entries.items():
            flags = nvidia_flags(entry)
            if flags is None:
                return None
            parsed[sid] = flags
        return parsed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def scan_nvidia(binary, skill_dirs):
    """Return id -> flags. A skill that never produces a report is marked failed.

    Failed skills stay in the denominator and count as not blocked. Their ids are
    returned separately so the public CSV can name them and the blind set can stay
    aggregate-only.
    """
    pending = [skill_dirs[i:i + 16] for i in range(0, len(skill_dirs), 16)]
    done = {}
    failed = {}
    with ThreadPoolExecutor(max_workers=min(4, len(pending) or 1)) as pool:
        inflight = {}
        def submit(batch):
            inflight[pool.submit(scan_nvidia_batch, binary, batch)] = batch
        for batch in pending:
            submit(batch)
        while inflight:
            fut = next(as_completed(list(inflight)))
            batch = inflight.pop(fut)
            parsed = fut.result()
            if parsed is None:
                if len(batch) == 1:
                    sid = os.path.basename(batch[0])
                    failed[sid] = True
                    done[sid] = dict(blocked=False, review=False, verdict='FAILED', failed=True)
                else:
                    mid = len(batch) // 2
                    submit(batch[:mid])
                    submit(batch[mid:])
            else:
                done.update(parsed)
    return done, failed

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
rule_hits = {}
public_ids = {s['id'] for s in M['skills']}
for top, label in SETS:
    p = subprocess.run(['node', cli, 'scan', '--json', '--allow-skipped', os.path.join(work, top, label)],
                       capture_output=True, text=True)
    if not p.stdout.strip():
        sys.exit(f'scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}')
    for s in json.loads(p.stdout)['skills']:
        sid = os.path.basename(os.path.realpath(s['root']))
        verdict[sid] = s['verdict']
        if sid in public_ids:
            rule_hits[sid] = sorted({f.get('ruleId', '') for f in s.get('findings', []) if f.get('ruleId')})

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
               msb_revision=msb['revision'], anthropic_commit=M['anthropic']['commit'],
               llm=dict(status='not-run',
                        note='Model opinion is a separate column. This command does not call a model, so it has no detection or false-positive count. It never changes the verdicts in this file.'))

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

nv = {}
nv_started = None
if nvidia:
    pin = pinned_nvidia_commit()
    got = installed_nvidia_commit(nvidia)
    if got != pin:
        sys.exit(f'SkillSpector install commit {got} does not match pin {pin}')
    nv_started = time.perf_counter()
    print(f'SkillSpector {got} static scan starting', file=sys.stderr)
    skill_dirs = []
    for top, label in SETS:
        base = os.path.join(work, top, label)
        skill_dirs.extend(os.path.join(base, name) for name in sorted(os.listdir(base)))
    nv, nv_failed = scan_nvidia(nvidia, skill_dirs)
    missing = [s['id'] for s in M['skills'] + B['skills'] if s['id'] not in nv]
    if missing:
        sys.exit(f'{len(missing)} skills missing from SkillSpector output')
    public_failed = sorted(s['id'] for s in M['skills'] if nv[s['id']]['failed'])
    blind_failed = sum(1 for s in B['skills'] if nv[s['id']]['failed'])
    nver = re.sub(r'\x1b\[[0-9;]*m', '', subprocess.run(
        [nvidia, '--version'], capture_output=True, text=True, check=True).stdout).strip()
    n = score({k: v['blocked'] for k, v in nv.items()})
    nx = extra({k: v['blocked'] for k, v in nv.items()}, {k: v['review'] for k, v in nv.items()})
    summary['nvidia'] = dict(version=nver, commit=pin,
                            command='skillspector scan <skill-dir> --no-llm --format json',
                            elapsed_seconds=round(time.perf_counter() - nv_started, 1),
                            scan_failures=dict(public=len(public_failed), blind=blind_failed,
                                               public_ids=public_failed,
                                               counted='not blocked and not review; still in the denominator'),
                            **{k: v for k, v in n.items() if not k.startswith('_')},
                            **{k: v[1] for k, v in nx.items()})

columns = [('ih', ih, ihx)]
if cisco:
    columns.append(('cisco', c, cx))
if nvidia:
    columns.append(('nvidia', n, nx))
if len(columns) > 1:
    # One green check per row, and only when a single scanner is strictly best.
    table_rows = (
        ('detect', True, lambda s, x: (s['_tp'], f"{s['detect_pct']}% ({s['detect']})")),
        ('fp', False, lambda s, x: (s['_fp'], f"{s['fp_pct']}% ({s['fp']})")),
        ('review-detect', True, lambda s, x: x['review_detect']),
        ('review-fp', False, lambda s, x: x['review_fp']),
        ('blind-detect', True, lambda s, x: x['blind_detect']),
        ('blind-fp', False, lambda s, x: x['blind_fp']),
        ('anthropic', False, lambda s, x: (s['_an'], s['anthropic'])),
    )
    for key, higher, getter in table_rows:
        measured = [(name, getter(s, x)) for name, s, x in columns]
        best = max(item[1][0] for item in measured) if higher else min(item[1][0] for item in measured)
        winners = [name for name, (count, _msg) in measured if count == best]
        winner = winners[0] if len(winners) == 1 else None
        for name, (_count, message) in measured:
            endpoint(f'table-{name}-{key}.json', message, name == winner)

# Proof files: per-skill verdicts for the public set, aggregate-only digest for the blind set
# (blind ids and per-skill verdicts are never published, so nobody can tune rules against them).
sha_c = os.environ.get('GITHUB_SHA') or subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
run_url = (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
           if os.environ.get('GITHUB_RUN_ID') else 'local run')
cver = summary.get('cisco', {}).get('version', '')
nver = summary.get('nvidia', {}).get('version', '')
with open(os.path.join(out_dir, 'results.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['row_id', 'label', 'scanner', 'scanner_version', 'verdict', 'counted_block', 'counted_block_or_review', 'timestamp_utc', 'commit_sha'])
    for s_ in M['skills']:
        v = verdict[s_['id']]
        w.writerow([s_['id'], s_['label'], 'ironheights', version, v, v == 'block', v in ('block', 'review'), stamp, sha_c])
        if cisco:
            w.writerow([s_['id'], s_['label'], 'cisco-skill-scanner', cver, cs_sev[s_['id']], cs[s_['id']], csr[s_['id']], stamp, sha_c])
        if nvidia:
            row = nv[s_['id']]
            w.writerow([s_['id'], s_['label'], 'nvidia-skillspector', nver, row['verdict'], row['blocked'], row['review'], stamp, sha_c])
def digest(fn):
    rows = sorted(f"{s_['id']}:{fn(s_['id'])}" for s_ in B['skills'])
    return hashlib.sha256('\n'.join(rows).encode()).hexdigest()
blind = dict(note='Aggregate only. sha256 is over sorted "id:verdict" lines; rerun the script to reproduce it.',
             ironheights=dict(version=version, detect=ihx['blind_detect'][1], fp=ihx['blind_fp'][1],
                              sha256=digest(lambda i: verdict[i])))
if cisco:
    blind['cisco'] = dict(version=cver, detect=cx['blind_detect'][1], fp=cx['blind_fp'][1], sha256=digest(lambda i: cs_sev[i]))
if nvidia:
    blind['nvidia'] = dict(version=nver, commit=summary['nvidia']['commit'],
                           detect=nx['blind_detect'][1], fp=nx['blind_fp'][1],
                           scan_failures=summary['nvidia']['scan_failures']['blind'],
                           sha256=digest(lambda i: nv[i]['verdict']))
json.dump(blind, open(os.path.join(out_dir, 'blind-aggregate.json'), 'w'), indent=1)
summary.update(run_url=run_url, commit_sha=sha_c, timestamp_utc=stamp)
open(os.path.join(out_dir, 'PROOF.md'), 'w').write(f"""# Benchmark proof

Every number in the README benchmark table comes from this run.

- Workflow run: {run_url}
- Commit: `{sha_c}`
- Time (UTC): {stamp}
- Ironheights {version}; Cisco skill-scanner {cver or 'not run'}; NVIDIA SkillSpector {nver or 'not run'} commit `{summary.get('nvidia', {}).get('commit', 'not run')}` (static analyzers only, no LLM)
- MaliciousSkillBench revision `{msb['revision']}`

| Row | Ironheights | Cisco | NVIDIA SkillSpector |
|---|---|---|---|
| Malicious detected (block) | {ih['detect']} | {summary.get('cisco', {}).get('detect', '')} | {summary.get('nvidia', {}).get('detect', '')} |
| Clean false positives (block) | {ih['fp']} | {summary.get('cisco', {}).get('fp', '')} | {summary.get('nvidia', {}).get('fp', '')} |
| Malicious block or review | {ihx['review_detect'][1]} | {summary.get('cisco', {}).get('review_detect', '')} | {summary.get('nvidia', {}).get('review_detect', '')} |
| Clean block or review | {ihx['review_fp'][1]} | {summary.get('cisco', {}).get('review_fp', '')} | {summary.get('nvidia', {}).get('review_fp', '')} |
| Blind attacks blocked | {ihx['blind_detect'][1]} | {summary.get('cisco', {}).get('blind_detect', '')} | {summary.get('nvidia', {}).get('blind_detect', '')} |
| Blind clean blocked | {ihx['blind_fp'][1]} | {summary.get('cisco', {}).get('blind_fp', '')} | {summary.get('nvidia', {}).get('blind_fp', '')} |
| Prose-only attacks blocked | {ihx['prose_detect'][1]} | {summary.get('cisco', {}).get('prose_detect', '')} | {summary.get('nvidia', {}).get('prose_detect', '')} |
| Prose-only attacks block or review | {ihx['prose_review'][1]} | {summary.get('cisco', {}).get('prose_review', '')} | {summary.get('nvidia', {}).get('prose_review', '')} |
| Anthropic skills flagged | {ih['anthropic']} | {summary.get('cisco', {}).get('anthropic', '')} | {summary.get('nvidia', {}).get('anthropic', '')} |

Prose-only = the 98 attacks with no code fence or shell/python line (`kind: prose` in the manifest; regex tag, see docs/benchmark.md).
Cisco has no review verdict: block = max severity HIGH or CRITICAL, block-or-review = MEDIUM or above.
NVIDIA SkillSpector (`--no-llm`): block = risk severity or max issue severity CRITICAL or HIGH, or recommendation DO_NOT_INSTALL. Block-or-review also counts MEDIUM or recommendation CAUTION. A skill that fails to scan counts as not blocked and stays in the denominator.

Files: [results.csv](results.csv) (one row per skill and scanner), [blind-aggregate.json](blind-aggregate.json)
(blind set counts and a digest only), [benchmark-summary.json](benchmark-summary.json).
How to reproduce: [docs/benchmark-proof.md](https://github.com/Frank-Masciopinto/ironheights/blob/main/docs/benchmark-proof.md).
""")
labels = {s['id']: s['label'] for s in M['skills']}
per_label = {'malicious': Counter(), 'benign': Counter()}
for sid, rules in rule_hits.items():
    lab = labels.get(sid)
    if lab not in per_label:
        continue
    for rule_id in rules:
        per_label[lab][rule_id] += 1
json.dump(dict(note='Public MaliciousSkillBench rows only. The blind set is not listed here.',
               counts={lab: dict(sorted(per_label[lab].items())) for lab in per_label},
               by_skill={sid: rule_hits[sid] for sid in sorted(rule_hits) if sid in labels}),
          open(os.path.join(out_dir, 'rules.json'), 'w'), indent=1)
json.dump(summary, open(os.path.join(out_dir, 'benchmark-summary.json'), 'w'), indent=1)
json.dump(dict(schemaVersion=1, label='MaliciousSkillBench',
               message=f"{ih['detect_pct']:.1f}% detect · {ih['fp_pct']:.1f}% FP", color='blue'),
          open(os.path.join(out_dir, 'benchmark.json'), 'w'), ensure_ascii=False)
print(json.dumps(summary))
