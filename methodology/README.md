# Methodology


## Initial Discovery

1) If you don't know where the target lives, use `netdiscover` to find it

```
sudo netdiscover -i eth0
```

2) Enumerate the target with `nmap`

```
nmap -Pn -v -p- -T4 ${TARGET_HOST}
```

3) Fingerprint services with `nmap`

```
nmap -Pn -v -p ${PORTS_FROM_2} -T4 -A ${TARGET_HOST}
```

4) Take notes of `nmap`'s results

- Any service versions available
- For HTTP Servers:
  - Any relevant HTTP headers 

## Webserver Enumeration

## Webserver Form Tampering



