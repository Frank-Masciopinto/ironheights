import json, os
TOKEN_CACHE = os.path.join(SCRIPT_DIR, ".token_cache.json")

def save(cache):
    with open(TOKEN_CACHE, "w", encoding="utf-8") as f:
        json.dump(cache, f)
