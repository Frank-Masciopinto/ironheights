#!/usr/bin/env python3
"""Score the attack-lanes benchmark set.

usage:
  python3 bench/script-skills/score.py \\
    [--pr dist/cli/index.js] \\
    [--main /path/to/main/cli.js] \\
    [--cisco skill-scanner] \\
    [--nvidia skillspector]

Generates samples/ from generate.py if needed and checks them against the
pinned manifest. Verdict mappings mirror scripts/benchmark-msb.py.
Writes results/{all,dev,heldout}/summary.json and per_sample.csv, plus
results/baseline.md. Nothing in the skill text is executed.
"""
from __future__ import annotations

import argparse, csv, json, os, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")
REPO = os.path.dirname(os.path.dirname(ROOT))


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def generate_and_check():
    gen = os.path.join(ROOT, "generate.py")
    if not os.path.isdir(SAMPLES) or not os.listdir(SAMPLES):
        p = run([sys.executable, gen], cwd=REPO)
        if p.returncode != 0:
            sys.exit(p.stderr or p.stdout or "generate.py failed")
        print(p.stdout, end="")
    p = run([sys.executable, gen, "--check"], cwd=REPO)
    if p.returncode != 0:
        sys.exit(p.stderr or "manifest check failed; rerun generate.py")
    print(p.stdout, end="")


def scan_ironheights(cli):
    p = run(["node", cli, "scan", "--json", "--allow-skipped", SAMPLES])
    if not p.stdout.strip():
        sys.exit(f"ironheights scan produced no output (exit {p.returncode}): {p.stderr[-2000:]}")
    out = {}
    for s in json.loads(p.stdout)["skills"]:
        sid = os.path.basename(os.path.realpath(s["root"]))
        out[sid] = s["verdict"]
    ver = run(["node", cli, "--version"]).stdout.strip()
    return out, ver


def scan_cisco(cisco):
    cs = {}
    with tempfile.TemporaryDirectory() as td:
        rep = os.path.join(td, "cisco.json")
        p = run([cisco, "scan-all", SAMPLES, "--format", "json", "--output", rep])
        if not os.path.exists(rep):
            sys.exit(f"cisco produced no report (exit {p.returncode}): {p.stderr[-2000:]}")
        for r in json.load(open(rep))["results"]:
            cs[os.path.basename(os.path.realpath(r["skill_path"]))] = r["max_severity"]
    cver = run([cisco, "--version"]).stdout.split()[-1]
    return cs, cver


NV_BLOCK = {"HIGH", "CRITICAL"}
NV_REVIEW = {"MEDIUM", "HIGH", "CRITICAL"}


def scan_nvidia(nvidia, ids):
    def one(sid):
        with tempfile.TemporaryDirectory() as td:
            rep = os.path.join(td, "r.json")
            try:
                proc = run([nvidia, "scan", os.path.join(SAMPLES, sid),
                            "--no-llm", "--format", "json", "--output", rep],
                           timeout=120)
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
        for sid, v in ex.map(one, ids):
            nv[sid] = v
    nver = run([nvidia, "--version"]).stdout.strip().split()[-1]
    return nv, nver


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", default=os.path.join(REPO, "dist", "cli", "index.js"))
    ap.add_argument("--main", default="")
    ap.add_argument("--cisco", default="skill-scanner")
    ap.add_argument("--nvidia", default="skillspector")
    args = ap.parse_args()
    generate_and_check()
    labels = json.load(open(os.path.join(ROOT, "labels.json")))["skills"]
    meta = {os.path.basename(e["path"]): e for e in labels}
    ids = sorted(meta)

    scanners = []  # (key, title, block_fn, review_fn, raw_fn)
    print("scanning Ironheights PR", args.pr, flush=True)
    ih_pr, pr_ver = scan_ironheights(args.pr)
    scanners.append(("ironheights_pr", f"Ironheights current ({pr_ver})",
                     lambda s: ih_pr.get(s) == "block",
                     lambda s: ih_pr.get(s) in ("block", "review"),
                     lambda s: ih_pr.get(s)))
    ih_main, main_ver = {}, ""
    if args.main:
        print("scanning Ironheights 0.36.0", args.main, flush=True)
        ih_main, main_ver = scan_ironheights(args.main)
        scanners.append(("ironheights_main", f"Ironheights 0.36.0 ({main_ver})",
                         lambda s, m=ih_main: m.get(s) == "block",
                         lambda s, m=ih_main: m.get(s) in ("block", "review"),
                         lambda s, m=ih_main: m.get(s)))
    print("scanning Cisco", args.cisco, flush=True)
    cs, cver = scan_cisco(args.cisco)
    scanners.append(("cisco", f"Cisco skill-scanner {cver}",
                     lambda s: cs.get(s) in ("HIGH", "CRITICAL"),
                     lambda s: cs.get(s) in ("MEDIUM", "HIGH", "CRITICAL"),
                     lambda s: cs.get(s)))
    print("scanning SkillSpector", args.nvidia, flush=True)
    nv, nver = scan_nvidia(args.nvidia, ids)
    scanners.append(("skillspector", f"NVIDIA SkillSpector {nver}",
                     lambda s: nv.get(s, {}).get("block", False),
                     lambda s: nv.get(s, {}).get("review", False),
                     lambda s: nv.get(s, {}).get("sev")))

    def tally(split, lane=None):
        if split == "all":
            sel = ids
        else:
            sel = [s for s in ids if meta[s]["split"] == split]
        if lane is not None:
            sel = [s for s in sel if meta[s].get("family") == lane]
        mal = [s for s in sel if meta[s]["label"] == "malicious"]
        ben = [s for s in sel if meta[s]["label"] == "benign"]
        out = {"attacks": len(mal), "benign": len(ben), "lane": lane}
        for key, _title, blk, rvw, _raw in scanners:
            blocked = sum(blk(s) for s in mal)
            rev_only = sum(rvw(s) and not blk(s) for s in mal)
            missed = len(mal) - blocked - rev_only
            fp = sum(blk(s) for s in ben)
            fp_rev = sum(rvw(s) and not blk(s) for s in ben)
            out[key] = dict(blocked=blocked, review=rev_only, block_or_review=blocked + rev_only,
                            missed=missed, benign_blocked=fp, benign_review=fp_rev,
                            benign_block_or_review=fp + fp_rev)
        return out

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    summary = {}
    lanes = sorted({meta[s].get("family") for s in ids if meta[s].get("family")})
    for split in ("all", "dev", "heldout"):
        t = tally(split)
        t["by_lane"] = {lane: tally(split, lane) for lane in lanes}
        summary[split] = t
        d = os.path.join(ROOT, "results", split)
        os.makedirs(d, exist_ok=True)
        json.dump(t, open(os.path.join(d, "summary.json"), "w"), indent=2)
        open(os.path.join(d, "summary.json"), "a").write("\n")
        with open(os.path.join(d, "per_sample.csv"), "w", newline="") as f:
            header = ["id", "label", "family", "split", "source"]
            for key, _title, _b, _r, _raw in scanners:
                header += [f"{key}_verdict", f"{key}_block", f"{key}_review"]
            w = csv.writer(f)
            w.writerow(header)
            rows = ids if split == "all" else [s for s in ids if meta[s]["split"] == split]
            for s in rows:
                row = [s, meta[s]["label"], meta[s]["family"], meta[s]["split"], meta[s].get("source", "")]
                for _key, _title, blk, rvw, raw in scanners:
                    row += [raw(s), blk(s), rvw(s)]
                w.writerow(row)

    def mdtable(split):
        t = summary[split]
        lines = [f"### {split} ({t['attacks']} attacks, {t['benign']} benign)", "",
                 "| Scanner | Attacks blocked | Block or review | Missed | Benign wrongly blocked | Benign block-or-review |",
                 "|---|---|---|---|---|---|"]
        for key, title, _b, _r, _raw in scanners:
            r = t[key]
            lines.append(
                f"| {title} | {r['blocked']}/{t['attacks']} | {r['block_or_review']}/{t['attacks']} | "
                f"{r['missed']}/{t['attacks']} | {r['benign_blocked']}/{t['benign']} | "
                f"{r['benign_block_or_review']}/{t['benign']} |"
            )
        lines += ["", "#### Per lane (attacks blocked / attacks)", "",
                  "| Lane | " + " | ".join(title for _k, title, *_ in scanners) + " |",
                  "|" + "---|" * (1 + len(scanners))]
        for lane, lt in sorted(t.get("by_lane", {}).items()):
            cells = []
            for key, _title, *_ in scanners:
                r = lt[key]
                cells.append(f"{r['blocked']}/{lt['attacks']}")
            lines.append(f"| {lane} | " + " | ".join(cells) + " |")
        return "\n".join(lines)

    report = (
        "# attack-lanes baseline\n\n"
        "DETECTION-80 lanes L1–L8. Generated by Ironheights (seed "
        "`attack-lanes-20261115`) plus real-derived missed-attacks, redteam, and "
        "settings-change fixtures. Ironheights 0.36.0 is `590ac5f`; current main is "
        "scored as `--pr`. Cisco has no review tier (MEDIUM+ counted as review). "
        "SkillSpector run with `--no-llm`. Held-out was scored once and not used to "
        "tune rules. Nothing was executed.\n\n"
        + mdtable("all") + "\n\n" + mdtable("dev") + "\n\n" + mdtable("heldout") + "\n"
    )
    open(os.path.join(ROOT, "results", "baseline.md"), "w").write(report)
    json.dump({"ironheights_pr": pr_ver, "ironheights_main": main_ver,
               "cisco": cver, "skillspector": nver, "splits": summary},
              open(os.path.join(ROOT, "results", "summary.json"), "w"), indent=2)
    open(os.path.join(ROOT, "results", "summary.json"), "a").write("\n")
    print(report)


if __name__ == "__main__":
    main()
