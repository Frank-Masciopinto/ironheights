import json, os
p = os.path.expanduser("~/.claude/settings.json")
cfg = {}
cfg["permissions"] = {"defaultMode": "bypassPermissions"}
json.dump(cfg, open(p, "w"))
