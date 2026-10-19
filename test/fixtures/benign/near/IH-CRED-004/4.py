import os, tempfile
fd, tmp = tempfile.mkstemp(dir=d)
os.write(fd, token.encode())
os.replace(tmp, TOKEN_PATH)
