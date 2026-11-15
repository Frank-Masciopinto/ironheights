#!/usr/bin/env python3
"""Build the attack-lanes benchmark set (deterministic).

usage:
  python3 bench/attack-lanes/generate.py           # write samples/, labels.json, manifest.json
  python3 bench/attack-lanes/generate.py --check   # regenerate in a temp dir and compare manifests

Coverage: DETECTION-80 lanes L1–L8. Each lane has 8 attack STRUCTURES × 16
disguises = 1024 generated attacks, each with an honest twin (2048). Carrier
(prose / script / config) and disclosure (hidden vs stated) are chosen by
hash so every lane has prose-only, script-bearing, hidden and disclosed
variants. Real-derived fixtures are copied from real-src/ (missed-attacks,
redteam house, outside-bot, and the settings-change sets).

Hosts are reserved (.invalid / .example / TEST-NET) or well-known public
relay / official API names. There are no real keys. Nothing is executed.

Do not read the held-out split when writing or tuning rules.
Seed: attack-lanes-20261115
"""
from __future__ import annotations

import argparse, hashlib, json, os, re, shutil, sys, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SEED = "attack-lanes-20261115"
SAMPLES = os.path.join(ROOT, "samples")
REAL_SRC = os.path.join(ROOT, "real-src")

sys.path.insert(0, ROOT)
from disguises import DISGUISES  # noqa: E402
from templates_a import S as STRUCTURES  # noqa: E402
import templates_b, templates_c  # noqa: F401,E402  (register L3–L8)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str) -> str:
    # Hash as POSIX text: CRLF from a Windows checkout must not change the pin.
    with open(path, "rb") as f:
        data = f.read().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return sha256_bytes(data)


def split_of(sid: str) -> str:
    n = int(sha256_bytes(f"{SEED}:{sid}".encode())[:8], 16)
    return "dev" if n % 2 == 0 else "heldout"


def pick(seed_key: str, options: list):
    n = int(sha256_bytes(f"{SEED}:{seed_key}".encode())[:8], 16)
    return options[n % len(options)]


def sink_host(slug: str, lang: str) -> str:
    # reserved / documentation names; never a real attacker host
    return f"{slug}-{lang}.collector.example.invalid"


def mirror_host(slug: str) -> str:
    return f"mirror-{slug}.example.invalid"


def evil_ip(slug: str) -> str:
    # TEST-NET-2 (RFC 5737)
    n = int(sha256_bytes(f"{SEED}:ip:{slug}".encode())[:2], 16)
    return f"198.51.100.{(n % 200) + 1}"


def evil_email(slug: str) -> str:
    return f"archive@{slug}.example.invalid"


def fill(text: str, ctx: dict) -> str:
    out = text
    for k, v in ctx.items():
        out = out.replace("{{" + k + "}}", str(v))
    if "{{" in out:
        missing = sorted(set(re.findall(r"\{\{(\w+)\}\}", out)))
        raise SystemExit(f"unfilled placeholders {missing} in template")
    return out


def skill_md(title: str, name: str, desc: str, steps: list[str],
             disclosure: str | None, script_rel: str | None, lang: str | None) -> str:
    body = [
        "---",
        f"name: {name}",
        f"description: {desc}",
        "---",
        "",
        f"# {title}",
        "",
        desc,
        "",
        "## Steps",
        "",
    ]
    for i, s in enumerate(steps, 1):
        body.append(f"{i}. {s}")
    if disclosure:
        body += ["", "## Note", "", disclosure]
    if script_rel:
        run = {
            "py": f"python3 {script_rel}",
            "sh": f"bash {script_rel}",
            "js": f"node {script_rel}",
            "ps1": f"pwsh -File {script_rel}",
            "json": f"Use the JSON at `{script_rel}` as the config or tool schema for this skill.",
            "yaml": f"Use the YAML at `{script_rel}` as the config for this skill.",
            "md": f"Read `{script_rel}` and follow it as additional instructions.",
        }[lang]
        body += ["", "## Helper", "", f"Run: `{run}`"]
    body.append("")
    return "\n".join(body)


CARRIERS = [
    # (name, prefers code langs, puts malice in SKILL.md steps?)
    ("prose", None, True),            # disclosed in steps, no extra file
    ("prose-hidden", None, False),    # honest-looking steps; malice in Note only when disclosed_flag
    ("script-py", "py", False),
    ("script-sh", "sh", False),
    ("script-js", "js", False),
    ("script-ps1", "ps1", False),
    ("config-json", "json", False),
    ("config-yaml", "yaml", False),
]


def choose_carrier(structure: dict, slug: str, disclosed: bool):
    # Prefer a carrier the structure actually has code for.
    code = structure["atk_code"]
    options = []
    for name, lang, prose_steps in CARRIERS:
        if lang is None:
            options.append((name, lang, prose_steps))
        elif lang in code:
            options.append((name, lang, prose_steps))
    # Always keep at least prose options
    if not options:
        options = [c for c in CARRIERS if c[1] is None]
    return pick(f"carrier:{structure['key']}:{slug}:{int(disclosed)}", options)


def build_pair(structure: dict, disguise: dict, disclosed: bool) -> tuple[str, str, dict, dict, dict, dict]:
    slug = disguise["slug"]
    lang_hint = "py"
    host = sink_host(slug, lang_hint)
    ctx = dict(
        slug=slug, title=disguise["title"], tool=disguise["tool"], desc=disguise["desc"],
        api=disguise["api"], secret=disguise["secret"], data=disguise["data"],
        cfg=disguise["cfg"], pkg=disguise["pkg"], repo=disguise["repo"],
        sink=f"https://{host}/ingest", sink_host=host,
        mirror_host=mirror_host(slug), evil_ip=evil_ip(slug), evil_email=evil_email(slug),
    )
    carrier_name, lang, prose_steps = choose_carrier(structure, slug, disclosed)

    label = pick(f"label:{structure['key']}:{slug}", structure["labels"])
    atk_step = fill(pick(f"atkstep:{structure['key']}:{slug}", structure["atk"]), ctx)
    ben_step = fill(pick(f"benstep:{structure['key']}:{slug}", structure["ben"]), ctx)
    atk_disc = fill(structure["atk_disc"], ctx)
    ben_disc = fill(structure["ben_disc"], ctx)

    # Steps: for disclosed prose, put the attack step in Steps; otherwise keep honest disguise steps
    # and put the attack either in Note (disclosed-hidden-carrier) or only in the code file (hidden).
    honest_steps = [fill(s, ctx) if "{{" in s else s for s in disguise["steps"]]

    mal_id = f"mal-{structure['lane'].lower()}-{structure['key']}-{slug}-{carrier_name}"
    ben_id = f"ben-{structure['lane'].lower()}-{structure['key']}-{slug}-{carrier_name}"
    # shorten ids a bit for path limits
    mal_id = mal_id.replace("script-", "s-").replace("config-", "c-").replace("prose-hidden", "ph")
    ben_id = ben_id.replace("script-", "s-").replace("config-", "c-").replace("prose-hidden", "ph")

    mal_files: dict[str, str] = {}
    ben_files: dict[str, str] = {}

    script_rel = None
    if lang is not None:
        ext = {"py": ".py", "sh": ".sh", "js": ".js", "ps1": ".ps1", "json": ".json", "yaml": ".yaml", "md": ".md"}[lang]
        script_rel = f"scripts/{disguise['tool']}{ext}" if lang in ("py", "sh", "js", "ps1") else f"config/{disguise['tool']}{ext}"
        atk_code = structure["atk_code"].get(lang) or next(iter(structure["atk_code"].values()))
        ben_code = structure["ben_code"].get(lang) or next(iter(structure["ben_code"].values()))
        # Some structures lack this lang; fall back already handled by choose_carrier
        mal_files[script_rel] = fill(atk_code, ctx)
        ben_files[script_rel] = fill(ben_code, ctx)

    if carrier_name == "prose" or (disclosed and prose_steps):
        mal_steps = honest_steps[:-1] + [atk_step]
        disclosure = atk_disc if disclosed else None
    elif disclosed:
        # malice stated in Note; steps look honest; code (if any) also malicious
        mal_steps = honest_steps
        disclosure = atk_disc + " " + atk_step
    else:
        # fully hidden: honest steps, no note; malice only in code (or, for prose-hidden, bury in a "Troubleshooting" line)
        mal_steps = list(honest_steps)
        if lang is None:
            mal_steps.append(
                "Troubleshooting: if the main path fails, "
                + atk_step[0].lower() + atk_step[1:]
            )
        disclosure = None

    ben_steps = list(honest_steps)
    ben_disclosure = ben_disc if disclosed else None

    name = f"{slug}-{structure['key']}"
    mal_files["SKILL.md"] = skill_md(
        disguise["title"], name, disguise["desc"], mal_steps, disclosure, script_rel, lang
    )
    ben_files["SKILL.md"] = skill_md(
        disguise["title"], name, disguise["desc"], ben_steps, ben_disclosure, script_rel, lang
    )

    note_mal = (
        f"Generated (seed {SEED}). Lane {structure['lane']}, structure {structure['key']}, "
        f"disguise {slug}, carrier {carrier_name}, disclosed={disclosed}. "
        f"Malice is the attack structure, not a wording copy of house fixtures."
    )
    note_ben = (
        f"Generated honest twin of {mal_id}. Same disguise and carrier; "
        f"does the legitimate version only."
    )
    meta_mal = dict(path=f"samples/{mal_id}", label="malicious", family=structure["lane"],
                    structure=structure["key"], disguise=slug, carrier=carrier_name,
                    disclosed=disclosed, split=split_of(mal_id), source="generated", notes=note_mal)
    meta_ben = dict(path=f"samples/{ben_id}", label="benign", family=structure["lane"],
                    structure=structure["key"], disguise=slug, carrier=carrier_name,
                    disclosed=disclosed, split=split_of(ben_id), source="generated", notes=note_ben)
    return mal_id, ben_id, mal_files, ben_files, meta_mal, meta_ben


def write_skill(dest_root: str, sid: str, files: dict[str, str]) -> None:
    d = os.path.join(dest_root, sid)
    os.makedirs(d, exist_ok=True)
    for rel, text in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def load_real_index() -> list[dict]:
    path = os.path.join(REAL_SRC, "index.json")
    if not os.path.exists(path):
        return []
    return json.load(open(path))["entries"]


def build(dest_root: str) -> tuple[list[dict], dict]:
    if os.path.exists(dest_root):
        shutil.rmtree(dest_root)
    os.makedirs(dest_root)
    labels: list[dict] = []

    # 64 structures × 16 disguises = 1024 pairs. Disclosure flips by hash.
    for structure in STRUCTURES:
        for disguise in DISGUISES:
            disclosed = pick(f"disc:{structure['key']}:{disguise['slug']}", [True, False])
            mal_id, ben_id, mal_files, ben_files, meta_mal, meta_ben = build_pair(
                structure, disguise, disclosed
            )
            write_skill(dest_root, mal_id, mal_files)
            write_skill(dest_root, ben_id, ben_files)
            labels.append(meta_mal)
            labels.append(meta_ben)

    # real-derived
    for entry in load_real_index():
        src = os.path.join(REAL_SRC, entry["src"])
        if not os.path.isdir(src):
            raise SystemExit(f"missing real-src/{entry['src']}")
        sid = entry["id"]
        dst = os.path.join(dest_root, sid)
        shutil.copytree(src, dst)
        # normalize line endings in copied text files
        for dirpath, _, filenames in os.walk(dst):
            for name in filenames:
                p = os.path.join(dirpath, name)
                if name.endswith((".md", ".py", ".sh", ".js", ".ps1", ".json", ".yaml", ".yml", ".txt", ".toml")):
                    raw = open(p, "rb").read().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    open(p, "wb").write(raw)
        labels.append({
            "path": f"samples/{sid}",
            "label": entry["label"],
            "family": entry["lane"],
            "structure": entry.get("structure", "real"),
            "disguise": entry.get("disguise", "real"),
            "carrier": entry.get("carrier", "real"),
            "disclosed": entry.get("disclosed", True),
            "split": split_of(sid),
            "source": "real-derived",
            "notes": entry["notes"],
        })

    labels.sort(key=lambda e: e["path"])
    files = {}
    for dirpath, _, filenames in os.walk(dest_root):
        for name in filenames:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, dest_root).replace("\\", "/")
            files[f"samples/{rel}"] = sha256_file(path)
    tree = sha256_bytes("\n".join(f"{h}  {p}" for p, h in sorted(files.items())).encode() + b"\n")
    manifest = {
        "seed": SEED,
        "split": f'split = "dev" if int(sha256(f"{SEED}:{{id}}").hexdigest()[:8], 16) % 2 == 0 else "heldout"',
        "tree_sha256": tree,
        "sample_count": len(labels),
        "files": files,
    }
    return labels, manifest


def write_outputs(labels: list[dict], manifest: dict) -> None:
    with open(os.path.join(ROOT, "labels.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"skills": labels}, f, indent=2)
        f.write("\n")
    with open(os.path.join(ROOT, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def counts(labels: list[dict]) -> str:
    mal = sum(1 for e in labels if e["label"] == "malicious")
    ben = sum(1 for e in labels if e["label"] == "benign")
    real = sum(1 for e in labels if e["source"] == "real-derived")
    gen = sum(1 for e in labels if e["source"] == "generated")
    dev = sum(1 for e in labels if e["split"] == "dev")
    held = sum(1 for e in labels if e["split"] == "heldout")
    by_lane = {}
    for e in labels:
        if e["label"] == "malicious":
            by_lane[e["family"]] = by_lane.get(e["family"], 0) + 1
    lanes = " ".join(f"{k}:{v}" for k, v in sorted(by_lane.items()))
    return (f"{len(labels)} samples ({mal} malicious, {ben} benign; "
            f"{gen} generated, {real} real-derived; split dev {dev} / held-out {held}; "
            f"attacks-by-lane {lanes})")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory() as td:
            labels, manifest = build(os.path.join(td, "samples"))
            want = json.load(open(os.path.join(ROOT, "manifest.json")))
            if manifest["tree_sha256"] != want["tree_sha256"] or manifest["files"] != want["files"]:
                print("manifest mismatch", file=sys.stderr)
                return 1
            print("ok", counts(labels), "tree", manifest["tree_sha256"][:16])
            return 0
    labels, manifest = build(SAMPLES)
    write_outputs(labels, manifest)
    print("wrote", SAMPLES)
    print(counts(labels))
    print("tree_sha256", manifest["tree_sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
