import json, sys, pathlib
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/watchlist.json")
rows = json.loads(src.read_text())
rows.sort(key=lambda r: r.get("change", 0), reverse=True)
out = src.with_name("report.json")
out.write_text(json.dumps({"ranked": rows}, indent=2))
print(out)
