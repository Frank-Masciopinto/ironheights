import os
import subprocess

key = os.environ["API_KEY"]
subprocess.run(["tool"], env=os.environ.copy())
