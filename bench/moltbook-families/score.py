#!/usr/bin/env python3
"""Score the moltbook-families benchmark set.

usage:
  python3 bench/moltbook-families/score.py \\
    --ih main=dist/cli/index.js \\
    --ih release=/path/to/0.37.0/dist/cli/index.js \\
    --cisco .venv/bin/skill-scanner \\
    --nvidia .venv/bin/skillspector

Generates samples/ if needed and checks the pinned manifest. Verdict mappings
match scripts/benchmark-msb.py. Writes results/{all,dev,heldout}/ and
results/baseline.md. Nothing in a skill is executed.

Held-out text is not an input to this script. It scores labels and verdicts.
"""
from __future__ import annotations

import argparse, csv, json, os, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")
REPO = os.path.dirname(os.path.dirname(ROOT))


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def generate_and_check():
    gen = os.path.join(ROOT, "generate.py")
    if not os.path.isdir(SAMPLES) or not os.listdir(SAMPLES):
        proc = run([sys.executable, gen], cwd=REPO)
        if proc.returncode != 0:
            sys.exit(proc.stderr or proc.stdout or "generate.py failed")
        print(proc.stdout, end="")
    proc = run([sys.executable, gen, "--check"], cwd=REPO)
    if proc.returncode != 0:
        sys.exit(proc.stderr or "manifest check failed; rerun generate.py")
    print(proc.stdout, end="")


def scan_ironheights(cli):
    proc = run(["node", cli, "scan", "--json", "--allow-skipped", SAMPLES])
    if not proc.stdout.strip():
        sys.exit(f"ironheights scan produced no output (exit {proc.returncode}): {proc.stderr[-2000:]}")
    out = {}
    for skill in json.loads(proc.stdout)["skills"]:
        sid = os.path.basename(os.path.realpath(skill["root"]))
        out[sid] = skill["verdict"]
    version = run(["node", cli, "--version"]).stdout.strip()
    return out, version


def scan_cisco(cisco):
    found = {}
    with tempfile.TemporaryDirectory() as temp:
        report = os.path.join(temp, "cisco.json")
        proc = run([cisco, "scan-all", SAMPLES, "--format", "json", "--output", report])
        if not os.path.exists(report):
            sys.exit(f"cisco produced no report (exit {proc.returncode}): {proc.stderr[-2000:]}")
        for row in json.load(open(report))["results"]:
            found[os.path.basename(os.path.realpath(row["skill_path"]))] = row["max_severity"]
    version = run([cisco, "--version"]).stdout.split()[-1]
    return found, version


NV_BLOCK = {"HIGH", "CRITICAL"}
NV_REVIEW = {"MEDIUM", "HIGH", "CRITICAL"}


def scan_nvidia(nvidia, ids):
    def one(sid):
        with tempfile.TemporaryDirectory() as temp:
            report = os.path.join(temp, "r.json")
            try:
                proc = run(
                    [nvidia, "scan", os.path.join(SAMPLES, sid), "--no-llm", "--format", "json", "--output", report],
                    timeout=120,
                )
            except subprocess.TimeoutExpired:
                return sid, {"sev": "TIMEOUT", "block": False, "review": False, "failed": True}
            if proc.returncode not in (0, 1) or not os.path.exists(report):
                return sid, {"sev": "FAILED", "block": False, "review": False, "failed": True}
            data = json.load(open(report))
            risk = data.get("risk_assessment") or {}
            severity = str(risk.get("severity") or "").upper()
            worst = str(risk.get("max_issue_severity") or "").upper()
            recommendation = str(risk.get("recommendation") or "").upper()
            failed = data.get("execution_successful") is False
            block = (severity in NV_BLOCK or worst in NV_BLOCK or recommendation == "DO_NOT_INSTALL") and not failed
            review = block or ((severity in NV_REVIEW or worst in NV_REVIEW or recommendation == "CAUTION") and not failed)
            return sid, {
                "sev": f"{severity}|{worst}|{recommendation}|score={risk.get('score')}",
                "block": block,
                "review": review,
                "failed": failed,
            }

    found = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for sid, value in pool.map(one, ids):
            found[sid] = value
    version = run([nvidia, "--version"]).stdout.strip().split()[-1]
    return found, version


def parse_ih(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise SystemExit(f"--ih expects name=path, got {value}")
    name, path = value.split("=", 1)
    return name, path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ih", action="append", default=[], help="name=path to an ironheights cli.js")
    parser.add_argument("--cisco", default="")
    parser.add_argument("--nvidia", default="")
    parser.add_argument("--out", default=os.path.join(ROOT, "results"))
    args = parser.parse_args()
    generate_and_check()
    labels = json.load(open(os.path.join(ROOT, "labels.json")))["skills"]
    meta = {os.path.basename(entry["path"]): entry for entry in labels}
    ids = sorted(meta)
    scanners = []

    versions = {}
    for name, path in [parse_ih(item) for item in args.ih]:
        print(f"scanning Ironheights {name}", path, flush=True)
        verdicts, version = scan_ironheights(path)
        versions[name] = version
        scanners.append(
            (
                name,
                f"Ironheights {name} ({version})",
                lambda sid, box=verdicts: box.get(sid) == "block",
                lambda sid, box=verdicts: box.get(sid) in ("block", "review"),
                lambda sid, box=verdicts: box.get(sid),
            )
        )
    if args.cisco:
        print("scanning Cisco", args.cisco, flush=True)
        cisco, cver = scan_cisco(args.cisco)
        versions["cisco"] = cver
        scanners.append(
            (
                "cisco",
                f"Cisco skill-scanner {cver}",
                lambda sid, box=cisco: box.get(sid) in ("HIGH", "CRITICAL"),
                lambda sid, box=cisco: box.get(sid) in ("MEDIUM", "HIGH", "CRITICAL"),
                lambda sid, box=cisco: box.get(sid),
            )
        )
    if args.nvidia:
        print("scanning SkillSpector", args.nvidia, flush=True)
        nvidia, nver = scan_nvidia(args.nvidia, ids)
        versions["skillspector"] = nver
        scanners.append(
            (
                "skillspector",
                f"NVIDIA SkillSpector {nver}",
                lambda sid: nvidia.get(sid, {}).get("block", False),
                lambda sid: nvidia.get(sid, {}).get("review", False),
                lambda sid: nvidia.get(sid, {}).get("sev"),
            )
        )
    if not scanners:
        sys.exit("name at least one scanner")

    def tally(split, family=None):
        selected = ids if split == "all" else [sid for sid in ids if meta[sid]["split"] == split]
        if family is not None:
            selected = [sid for sid in selected if meta[sid].get("family") == family]
        malicious = [sid for sid in selected if meta[sid]["label"] == "malicious"]
        benign = [sid for sid in selected if meta[sid]["label"] == "benign"]
        out = {"attacks": len(malicious), "benign": len(benign), "family": family}
        for key, _title, block, review, _raw in scanners:
            blocked = sum(block(sid) for sid in malicious)
            review_only = sum(review(sid) and not block(sid) for sid in malicious)
            false_positives = sum(block(sid) for sid in benign)
            false_review = sum(review(sid) and not block(sid) for sid in benign)
            out[key] = {
                "blocked": blocked,
                "review": review_only,
                "block_or_review": blocked + review_only,
                "missed": len(malicious) - blocked - review_only,
                "benign_blocked": false_positives,
                "benign_review": false_review,
                "benign_block_or_review": false_positives + false_review,
            }
        return out

    os.makedirs(args.out, exist_ok=True)
    summary = {}
    families = sorted({meta[sid].get("family") for sid in ids})
    for split in ("all", "dev", "heldout"):
        total = tally(split)
        total["by_family"] = {family: tally(split, family) for family in families}
        summary[split] = total
        folder = os.path.join(args.out, split)
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, "summary.json"), "w", encoding="utf-8") as handle:
            json.dump(total, handle, indent=2)
            handle.write("\n")
        with open(os.path.join(folder, "per_sample.csv"), "w", newline="", encoding="utf-8") as handle:
            header = ["id", "label", "family", "structure", "split", "form", "layout"]
            for key, _title, _block, _review, _raw in scanners:
                header += [f"{key}_verdict", f"{key}_block", f"{key}_review"]
            writer = csv.writer(handle)
            writer.writerow(header)
            rows = ids if split == "all" else [sid for sid in ids if meta[sid]["split"] == split]
            for sid in rows:
                row = [
                    sid,
                    meta[sid]["label"],
                    meta[sid]["family"],
                    meta[sid].get("structure", ""),
                    meta[sid]["split"],
                    meta[sid].get("form", ""),
                    meta[sid].get("layout", ""),
                ]
                for _key, _title, block, review, raw in scanners:
                    row += [raw(sid), block(sid), review(sid)]
                writer.writerow(row)

    def mdtable(split):
        total = summary[split]
        lines = [
            f"### {split} ({total['attacks']} attacks, {total['benign']} benign)",
            "",
            "| Scanner | Attacks blocked | Block or review | Missed | Benign wrongly blocked | Benign block-or-review |",
            "|---|---|---|---|---|---|",
        ]
        for key, title, _block, _review, _raw in scanners:
            row = total[key]
            lines.append(
                f"| {title} | {row['blocked']}/{total['attacks']} | {row['block_or_review']}/{total['attacks']} | "
                f"{row['missed']}/{total['attacks']} | {row['benign_blocked']}/{total['benign']} | "
                f"{row['benign_block_or_review']}/{total['benign']} |"
            )
        lines += [
            "",
            "#### Per family (attacks blocked / attacks, benign blocked / benign)",
            "",
            "| Family | " + " | ".join(title for _key, title, *_rest in scanners) + " |",
            "|" + "---|" * (1 + len(scanners)),
        ]
        for family, bucket in sorted(total.get("by_family", {}).items()):
            cells = []
            for key, _title, *_rest in scanners:
                row = bucket[key]
                cells.append(f"{row['blocked']}/{bucket['attacks']} (twins {row['benign_blocked']}/{bucket['benign']})")
            lines.append(f"| {family} | " + " | ".join(cells) + " |")
        return "\n".join(lines)

    manifest = json.load(open(os.path.join(ROOT, "manifest.json"), encoding="utf-8"))
    report = (
        "# moltbook-families scores\n\n"
        f"Set `{manifest['set_version']}`, seed `{manifest['seed']}`, tree `{manifest['tree_sha256']}`.\n\n"
        "Generated by Ironheights. Not an independent corpus. Held-out was scored and is not an input "
        "to rule writing. Cisco has no separate review tier (MEDIUM and above count as review). "
        "SkillSpector is `--no-llm`. Block for NVIDIA is critical or high severity, or "
        "`DO_NOT_INSTALL`. Nothing was executed.\n\n"
        + mdtable("all")
        + "\n\n"
        + mdtable("dev")
        + "\n\n"
        + mdtable("heldout")
        + "\n"
    )
    with open(os.path.join(args.out, "baseline.md"), "w", encoding="utf-8") as handle:
        handle.write(report)
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as handle:
        json.dump({"versions": versions, "set_version": manifest["set_version"], "tree_sha256": manifest["tree_sha256"], "splits": summary}, handle, indent=2)
        handle.write("\n")
    print(report)


if __name__ == "__main__":
    main()
