import os

a = os.getenv("API_KEY", "your-api-key-here")
b = os.getenv("TOKEN", "changeme")
c = os.getenv("SECRET", "xxx")
d = os.getenv("PASSWORD", "<KEY>")
e = os.environ.get(
    "API_KEY",
    "your-api-key-here-please-replace-this-now",
)
f = os.getenv("API_KEY") or os.getenv("BACKUP_API_KEY")
g = os.getenv("API_KEY", "sk-your-api-key-here")
h = os.getenv("TOKEN", "change-me")
