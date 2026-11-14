#!/usr/bin/env python3
"""Score the settings-change benchmark set, split by dev / heldout.

usage: score.py [<cli.js>] [<cisco skill-scanner>] [<skillspector>]

Defaults: dist/cli/index.js (built Ironheights CLI) and the scanners are looked up
on PATH. Verdict mappings mirror scripts/benchmark-msb.py exactly:
  Ironheights: CLI 'verdict' field. block = 'block'; review = block or 'review'.
  Cisco:  max_severity HIGH/CRITICAL = block; MEDIUM+ = block-or-review (no review tier).
  NVIDIA SkillSpector (--no-llm): risk severity or max issue severity CRITICAL/HIGH,
    or recommendation DO_NOT_INSTALL = block; MEDIUM or CAUTION also counts for review.
    A skill that fails to scan counts as not blocked and stays in the denominator.
Writes results/<split>/summary.json and results/<split>/per_sample.csv, plus
results/baseline.md. Nothing in the skill text is executed."""
import csv, json, os, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")
cli = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else os.path.join(
    os.path.dirname(os.path.dirname(ROOT)), "dist", "cli", "index.js")
cisco = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else "skill-scanner"
nvidia = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "skillspector"

labels = json.load(open(os.path.join(ROOT, "labels.json")))["skills"]
meta = {os.path.basename(e["path"]): e for e in labels}
ids = sorted(meta)

# ---- Ironheights: one scan over the whole samples tree
ih = {}
p = subprocess.run(["node", cli, "scan", "--json", "--allow-skipped", SAMPLES],
                   capture_output=True, text=True)
if not p.stdout.strip():
    sys.exit(f"ironheights scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}")
for s in json.loads(p.stdout)["skills"]:
    sid = os.path.basename(os.path.realpath(s["root"]))
    ih[sid] = s["verdict"]

# ---- Cisco: one scan-all over the tree
cs = {}
with tempfile.TemporaryDirectory() as td:
    rep = os.path.join(td, "cisco.json")
    subprocess.run([cisco, "scan-all", SAMPLES, "--format", "json", "--output", rep],
                   capture_output=True, text=True)
    if not os.path.exists(rep):
        sys.exit("cisco produced no report")
    for r in json.load(open(rep))["results"]:
        cs[os.path.basename(os.path.realpath(r["skill_path"]))] = r["max_severity"]
cver = subprocess.run([cisco, "--version"], capture_output=True, text=True).stdout.split()[-1]

# ---- NVIDIA SkillSpector: per-sample, parallel
NV_BLOCK = {"HIGH", "CRITICAL"}
NV_REVIEW = {"MEDIUM", "HIGH", "CRITICAL"}
def scan_nv(sid):
    with tempfile.TemporaryDirectory() as td:
        rep = os.path.join(td, "r.json")
        try:
            proc = subprocess.run([nvidia, "scan", os.path.join(SAMPLES, sid),
                                   "--no-llm", "--format", "json", "--output", rep],
                                  capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return sid, dict(sev="TIMEOUT", block=False, review=False, failed=True)
        if proc.returncode not in (0, 1) or not os.path.exists(rep):
            return sid, dict(sev="FAILED", block=False, review=False, failed=True)
        d = json.load(open(rep))
        ra = d.get("risk_assessment") or {}
        sev = str(ra.get("severity") or "").upper()
        worst = str(ra.get("max_issue_severity") or "").upper()
        rec = str(ra.get("recommendation") or "").upper()
        failed = d.get("execution_successful") is False
        block = (sev in NV_BLOCK or worst in NV_BLOCK or rec == "DO_NOT_INSTALL") and not failed
        review = block or ((sev in NV_REVIEW or worst in NV_REVIEW or rec == "CAUTION") and not failed)
        return sid, dict(sev=f"{sev}|{worst}|{rec}|score={ra.get('score')}",
                         block=block, review=review, failed=failed)
nv = {}
with ThreadPoolExecutor(max_workers=8) as ex:
    for sid, v in ex.map(scan_nv, ids):
        nv[sid] = v
nver = subprocess.run([nvidia, "--version"], capture_output=True, text=True).stdout.strip().split()[-1]

# ---- verdict helpers
def ih_block(sid): return ih.get(sid) == "block"
def ih_review(sid): return ih.get(sid) in ("block", "review")
def cs_block(sid): return cs.get(sid) in ("HIGH", "CRITICAL")
def cs_review(sid): return cs.get(sid) in ("MEDIUM", "HIGH", "CRITICAL")
def nv_block(sid): return nv.get(sid, {}).get("block", False)
def nv_review(sid): return nv.get(sid, {}).get("review", False)

def tally(split):
    sel = [s for s in ids if meta[s]["split"] == split]
    mal = [s for s in sel if meta[s]["label"] == "malicious"]
    ben = [s for s in sel if meta[s]["label"] == "benign"]
    def row(blk, rvw):
        blocked = sum(blk(s) for s in mal)
        rev_only = sum(rvw(s) and not blk(s) for s in mal)
        missed = len(mal) - blocked - rev_only
        fp = sum(blk(s) for s in ben)
        fp_rev = sum(rvw(s) and not blk(s) for s in ben)
        return dict(attacks=len(mal), benign=len(ben),
                    blocked=blocked, review=rev_only, missed=missed,
                    benign_blocked=fp, benign_review=fp_rev)
    return dict(ironheights=row(ih_block, ih_review),
                cisco=row(cs_block, cs_review),
                skillspector=row(nv_block, nv_review))

os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
summary = {}
for split in ("dev", "heldout"):
    t = tally(split)
    summary[split] = t
    d = os.path.join(ROOT, "results", split)
    os.makedirs(d, exist_ok=True)
    json.dump(t, open(os.path.join(d, "summary.json"), "w"), indent=2)
    with open(os.path.join(d, "per_sample.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "family",
                    "ironheights_verdict", "ih_block", "ih_review",
                    "cisco_max_severity", "cisco_block", "cisco_review",
                    "skillspector_verdict", "ss_block", "ss_review"])
        for s in sorted(s for s in ids if meta[s]["split"] == split):
            w.writerow([s, meta[s]["label"], meta[s]["family"],
                        ih.get(s), ih_block(s), ih_review(s),
                        cs.get(s), cs_block(s), cs_review(s),
                        nv.get(s, {}).get("sev"), nv_block(s), nv_review(s)])

ver = subprocess.run(["node", cli, "--version"], capture_output=True, text=True).stdout.strip()
def mdtable(split):
    t = summary[split]
    lines = [f"### {split}", "",
             "| Scanner | Attacks | Blocked | Review | Missed | Benign | Benign wrongly blocked |",
             "|---|---|---|---|---|---|---|"]
    for name, key in [("Ironheights " + ver, "ironheights"),
                      (f"Cisco skill-scanner {cver}", "cisco"),
                      (f"NVIDIA SkillSpector {nver}", "skillspector")]:
        r = t[key]
        lines.append(f"| {name} | {r['attacks']} | {r['blocked']} | {r['review']} | "
                     f"{r['missed']} | {r['benign']} | {r['benign_blocked']} |")
    return "\n".join(lines)
with open(os.path.join(ROOT, "results", "baseline.md"), "w") as f:
    f.write("# settings-change baseline\n\n"
            "Block / review / missed on attacks, and benign wrongly blocked, per split. "
            "Cisco has no review tier (MEDIUM+ counted as review). SkillSpector run with `--no-llm`.\n\n")
    f.write(mdtable("dev") + "\n\n" + mdtable("heldout") + "\n")
print(open(os.path.join(ROOT, "results", "baseline.md")).read())
