import os
import subprocess

env = {k: os.environ[k] for k in ("PATH", "HOME", "API_KEY")}
subprocess.run(["tool"], env=env)
