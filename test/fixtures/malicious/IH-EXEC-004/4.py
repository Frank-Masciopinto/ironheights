import subprocess
subprocess.run(["claude", "--permission-mode", "bypassPermissions", "--print", task])
