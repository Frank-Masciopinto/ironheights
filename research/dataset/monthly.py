#!/usr/bin/env python3
"""Monthly public AI-skill security dataset (Ironheights).

Read-only. Nothing from a skill is executed or unpacked: files are written as inert bytes and
scanned by a pinned ironheights CLI inside a bubblewrap sandbox (no network, read-only root,
empty HOME) when bwrap is available.

Steps (each resumable; run them in order):
  list     crawl the public ClawHub catalog (GET /api/v1/skills, paged)      -> <out>/catalog.json
  select   choose skills: top N by downloads + seeded uniform sample of the rest, or --all
  fetch    per-file public API for each selected skill's latest version (no zip download, so
           author download counters are not inflated)                          -> <out>/work/
  scan     ironheights scan <skill> --json per skill                            -> <out>/raw/
  publish  anonymised open data (CC BY 4.0): skills.csv, skills.json, summary.json -> <out>/public/

Privacy: public files carry no slug, owner or skill text. Each row has an opaque id
(sha256 of month salt + owner/slug, salt kept private in <out>/private/), so a row can be
disclosed to its author on request without publishing a name list.

Usage example:
  python3 monthly.py all --month 2026-10 --out /data/ih-2026-10 \
      --ironheights /path/to/node_modules/.bin/ironheights --top 2000 --sample 2000
"""
import argparse, csv, hashlib, json, os, random, secrets, shutil, subprocess, sys, threading, time
import urllib.error, urllib.parse, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

API = "https://clawhub.ai/api/v1/skills"
UA = {"User-Agent": "ironheights-monthly-dataset/1.0 (+https://www.ironheights.dev/reports/; read-only research)"}
LIM = 1048576
_lock = threading.Lock()
STATS = Counter()


def get(url, raw=False, tries=6):
    for i in range(tries):
        try:
            with _lock:
                STATS["requests"] += 1
            body = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60).read()
            return body if raw else json.loads(body)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                with _lock:
                    STATS["http429"] += 1
                retry = e.headers.get("Retry-After")
                time.sleep(float(retry) if retry and retry.isdigit() else 15 + 10 * i)
                continue
            if e.code in (403, 404, 410):
                return None
            time.sleep(2 + i)
        except Exception:
            time.sleep(2 + i)
    return None


def p(out, *parts):
    return os.path.join(out, *parts)


def step_list(a):
    items, cursor, page = [], None, 0
    while True:
        q = {"limit": 200, "sort": "downloads"}
        if cursor:
            q["cursor"] = cursor
        d = get(API + "?" + urllib.parse.urlencode(q))
        if d is None:
            print("list: page failed, stopping", file=sys.stderr)
            break
        items += d.get("items", [])
        page += 1
        cursor = d.get("nextCursor")
        if page % 25 == 0:
            print(f"list: {page} pages, {len(items)} skills", flush=True)
        if not cursor:
            break
        time.sleep(a.delay)
    seen, uniq = set(), []
    for x in items:
        k = (x.get("ownerHandle"), x.get("slug"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(x)
    json.dump({"crawledAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "count": len(uniq), "items": uniq},
              open(p(a.out, "catalog.json"), "w"))
    print(f"list: {len(uniq)} unique skills")


def key(x):
    return f"{x.get('ownerHandle')}/{x.get('slug')}"


def step_select(a):
    cat = json.load(open(p(a.out, "catalog.json")))["items"]
    cat = [x for x in cat if (x.get("latestVersion") or {}).get("version") and x.get("ownerHandle")]
    cat.sort(key=lambda x: -((x.get("stats") or {}).get("downloads") or 0))
    if a.all:
        chosen = [(x, "all") for x in cat]
    else:
        top = cat[: a.top]
        rest = cat[a.top:]
        rnd = random.Random(f"ironheights-{a.month}")
        sample = rnd.sample(rest, min(a.sample, len(rest)))
        chosen = [(x, "top") for x in top] + [(x, "sample") for x in sample]
    sel = [{"key": key(x), "owner": x["ownerHandle"], "slug": x["slug"], "version": x["latestVersion"]["version"],
            "stratum": s, "downloads": (x.get("stats") or {}).get("downloads") or 0,
            "installs": (x.get("stats") or {}).get("installs") or 0} for x, s in chosen]
    json.dump({"month": a.month, "catalogCount": len(cat), "top": a.top, "sample": a.sample, "all": a.all,
               "selected": sel}, open(p(a.out, "private", "selection.json"), "w"))
    print(f"select: {len(sel)} of {len(cat)}")


def safe(path):
    path = path.replace("\\", "/")
    return path and not path.startswith("/") and ".." not in path.split("/") and "\x00" not in path


def sid(s):
    return hashlib.sha256(s["key"].encode()).hexdigest()[:16]


def fetch_one(a, s):
    mp = p(a.out, "work", "manifest", sid(s) + ".json")
    if os.path.exists(mp):
        return "skip"
    q = "?owner=" + urllib.parse.quote(s["owner"])
    base = API + "/" + urllib.parse.quote(s["slug"])
    m = {"key": s["key"], "ok": False}
    det = get(base + q)
    if det:
        mod = det.get("moderation") or {}
        m.update(clawhubVerdict=mod.get("verdict"), clawhubSuspicious=mod.get("isSuspicious"),
                 clawhubMalwareBlocked=mod.get("isMalwareBlocked"))
    ver = get(base + "/versions/" + urllib.parse.quote(s["version"]) + q)
    if not ver or not (ver.get("version") or {}).get("files"):
        m["error"] = "no version files"
        json.dump(m, open(mp, "w"))
        return "fail"
    root = p(a.out, "work", "skills", sid(s), "skill")
    os.makedirs(root, exist_ok=True)
    files = []
    for f in ver["version"]["files"]:
        rec = {"path": f["path"], "size": f.get("size", 0)}
        if not safe(f["path"]):
            rec["status"] = "unsafe-path-skipped"
            files.append(rec)
            continue
        dest = os.path.join(root, f["path"])
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
        except OSError:
            rec["status"] = "path-conflict"
            files.append(rec)
            continue
        if rec["size"] > LIM:
            with open(dest, "wb") as fh:
                fh.truncate(rec["size"])
            rec["status"] = "placeholder-over-1MiB"
        else:
            b = get(base + "/file?path=" + urllib.parse.quote(f["path"]) + "&version=" +
                    urllib.parse.quote(s["version"]) + "&owner=" + urllib.parse.quote(s["owner"]), raw=True)
            if b is None:
                rec["status"] = "fetch-failed"
            else:
                try:
                    open(dest, "wb").write(b)
                    rec["status"] = "ok" if hashlib.sha256(b).hexdigest() == f.get("sha256") else "sha-mismatch"
                except OSError:
                    rec["status"] = "path-conflict"
        files.append(rec)
    m["files"] = files
    m["ok"] = True
    json.dump(m, open(mp, "w"))
    return "ok"


def step_fetch(a):
    sel = json.load(open(p(a.out, "private", "selection.json")))["selected"]
    os.makedirs(p(a.out, "work", "manifest"), exist_ok=True)
    c = Counter()
    t0 = time.time()
    with ThreadPoolExecutor(a.workers) as ex:
        for i, r in enumerate(ex.map(lambda s: fetch_one(a, s), sel)):
            c[r] += 1
            if i % 200 == 0:
                print(f"fetch: {i}/{len(sel)} {dict(c)} req={STATS['requests']} 429={STATS['http429']} "
                      f"{time.time() - t0:.0f}s", flush=True)
    print("fetch:", dict(c), dict(STATS))


def scan_one(a, s):
    i = sid(s)
    out = p(a.out, "raw", i + ".json")
    meta = p(a.out, "raw", i + ".meta.json")
    if os.path.exists(meta):
        return "skip"
    try:
        m = json.load(open(p(a.out, "work", "manifest", i + ".json")))
    except Exception:
        return "nofetch"
    if not m.get("ok"):
        return "nofetch"
    d = os.path.abspath(p(a.out, "work", "skills", i, "skill"))
    cmd = [a.ironheights, "scan", d, "--json", "--no-color"]
    if shutil.which("bwrap") and not a.no_sandbox:
        cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/tmp", "--unshare-all",
               "--die-with-parent", "--chdir", "/tmp", "--setenv", "HOME", "/tmp", "--setenv", "NO_COLOR", "1",
               "--setenv", "IRONHEIGHTS_NO_UPDATE", "1"] + cmd
    try:
        with open(out, "wb") as fh:
            r = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, timeout=120)
        rc, err = r.returncode, r.stderr[-300:].decode("utf8", "replace")
    except subprocess.TimeoutExpired:
        rc, err = -9, "timeout"
    json.dump({"exit": rc, "stderr": err}, open(meta, "w"))
    return f"exit{rc}"


def step_scan(a):
    sel = json.load(open(p(a.out, "private", "selection.json")))["selected"]
    os.makedirs(p(a.out, "raw"), exist_ok=True)
    ver = subprocess.run([a.ironheights, "--version"], capture_output=True, text=True).stdout.strip()
    json.dump({"ironheights": ver}, open(p(a.out, "private", "scanner.json"), "w"))
    c = Counter()
    with ThreadPoolExecutor(a.scan_workers) as ex:
        for i, r in enumerate(ex.map(lambda s: scan_one(a, s), sel)):
            c[r] += 1
            if i % 500 == 0:
                print(f"scan: {i}/{len(sel)} {dict(c)}", flush=True)
    print("scan:", dict(c), "ironheights", ver)


NOISY = {"IH-NET-001", "IH-FS-001", "IH-META-001"}


def bucket(n):
    for lim, lab in ((10, "0-9"), (100, "10-99"), (1000, "100-999"), (10000, "1k-9.9k")):
        if n < lim:
            return lab
    return "10k+"


def step_publish(a):
    selj = json.load(open(p(a.out, "private", "selection.json")))
    sel = selj["selected"]
    saltp = p(a.out, "private", "salt.txt")
    if not os.path.exists(saltp):
        open(saltp, "w").write(secrets.token_hex(16))
    salt = open(saltp).read().strip()
    scanner = json.load(open(p(a.out, "private", "scanner.json"))).get("ironheights", "")
    rows, rule_count, rule_skills, owasp_skills, cre_skills, rule_refs = [], Counter(), Counter(), Counter(), Counter(), {}
    verdicts, strata = Counter(), Counter()
    disclosure = []
    for s in sel:
        i = sid(s)
        try:
            meta = json.load(open(p(a.out, "raw", i + ".meta.json")))
            res = json.load(open(p(a.out, "raw", i + ".json")))
            man = json.load(open(p(a.out, "work", "manifest", i + ".json")))
        except Exception:
            continue
        findings = [f for sk in res.get("skills", []) for f in sk.get("findings", [])]
        rules = Counter(f["ruleId"] for f in findings)
        owasp, cre = set(), set()
        for f in findings:
            refs = f.get("references") or {}
            rule_refs.setdefault(f["ruleId"], {"owaspLlm": refs.get("owaspLlm", []), "openCre": refs.get("openCre", [])})
            owasp.update(refs.get("owaspLlm", []))
            cre.update(refs.get("openCre", []))
        strong = sorted(r for r in rules if r not in NOISY)
        rid = hashlib.sha256((salt + s["key"]).encode()).hexdigest()[:12]
        row = {
            "id": rid, "stratum": s["stratum"], "downloads_bucket": bucket(s["downloads"]),
            "files": len(man.get("files", [])), "verdict": res.get("verdict", ""),
            "grade": (res.get("grade") or {}).get("letter", ""), "score": (res.get("grade") or {}).get("score", ""),
            "findings": len(findings), "rules": ";".join(sorted(rules)), "strong_rules": ";".join(strong),
            "owasp_llm": ";".join(sorted(owasp)), "opencre": ";".join(sorted(cre)),
            "clawhub_verdict": man.get("clawhubVerdict") or "", "scan_exit": meta.get("exit"),
        }
        rows.append(row)
        verdicts[row["verdict"]] += 1
        strata[s["stratum"]] += 1
        for r, n in rules.items():
            rule_count[r] += n
            rule_skills[r] += 1
        for o in owasp:
            owasp_skills[o] += 1
        for c in cre:
            cre_skills[c] += 1
        if row["verdict"] == "block" and strong:
            disclosure.append({"id": rid, "key": s["key"], "version": s["version"], "strong_rules": strong})
    pub = p(a.out, "public")
    os.makedirs(pub, exist_ok=True)
    fields = list(rows[0].keys()) if rows else []
    with open(p(pub, "skills.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    lic = "CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/), attribution: Ironheights (https://www.ironheights.dev)"
    json.dump({"license": lic, "month": a.month, "rows": rows}, open(p(pub, "skills.json"), "w"))
    n = len(rows)
    strong_any = sum(1 for r in rows if r["strong_rules"])
    summary = {
        "license": lic, "month": a.month, "source": "ClawHub public API (clawhub.ai)", "scanner": scanner,
        "catalogCount": selj["catalogCount"], "selection": {"top": selj["top"], "sample": selj["sample"], "all": selj["all"]},
        "scanned": n, "byStratum": dict(strata), "verdicts": dict(verdicts),
        "withStrongFinding": strong_any, "noisyRules": sorted(NOISY),
        "rules": [{"ruleId": r, "findings": rule_count[r], "skills": rule_skills[r], **rule_refs.get(r, {})}
                  for r in sorted(rule_skills, key=lambda r: -rule_skills[r])],
        "owaspLlmSkills": dict(owasp_skills.most_common()), "openCreSkills": dict(cre_skills.most_common()),
        "clawhubVerdicts": dict(Counter(r["clawhub_verdict"] or "none" for r in rows)),
        "requests": dict(STATS),
        "caveat": "A flag is a pattern match for a human to review, not proof that a skill is malicious. "
                  "Absence of findings is not proof of safety.",
    }
    json.dump(summary, open(p(pub, "summary.json"), "w"), indent=1)
    json.dump(disclosure, open(p(a.out, "private", "disclosure-queue.json"), "w"), indent=1)
    print(f"publish: {n} rows, {strong_any} with a strong-rule finding, disclosure queue {len(disclosure)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["list", "select", "fetch", "scan", "publish", "all"])
    ap.add_argument("--month", required=True, help="YYYY-MM")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ironheights", default="ironheights", help="path to a pinned ironheights binary")
    ap.add_argument("--top", type=int, default=2000)
    ap.add_argument("--sample", type=int, default=2000)
    ap.add_argument("--all", action="store_true", help="every listed skill (about a day of polite fetching)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--scan-workers", type=int, default=4)
    ap.add_argument("--delay", type=float, default=0.2, help="seconds between catalog pages")
    ap.add_argument("--no-sandbox", action="store_true")
    a = ap.parse_args()
    os.makedirs(p(a.out, "private"), exist_ok=True)
    steps = ["list", "select", "fetch", "scan", "publish"] if a.step == "all" else [a.step]
    for s in steps:
        globals()["step_" + s](a)


if __name__ == "__main__":
    main()
