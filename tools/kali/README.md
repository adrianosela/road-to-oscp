# Kali (Tools)

- [openvpn](#openvpn): OSCP Labs Environment VPN client
- [netdiscover](#netdiscover): Discover network members by listening for ARP
- [nmap](#nmap): FIXME
- [gobuster](#gobuster): FIXME
- [searchsploit](#searchsploit): FIXME
- [msfvenom](#msfvenom): FIXME
- [hydra](#hydra): FIXME
- [hashcat](#hashcat): FIXME

## openvpn

During the lab they will give you the URL of an OpenVNC Access Server, where you will authenticate with your lab credentials and be able to download an OpenVPN profile (i.e. a `.ovpn` file).

You can then connect to the VPN with the profile with:

```
sudo openvpn *.ovpn
```

You should immediately have a private IP for the network you joined.

## netdiscover

Discover network members by listening for ARP


```
netdiscover -i ${INTERFACE}
```

e.g.

```
netdiscover -i eth0
```

## nmap

// FIXME

## gobuster

// FIXME

## searchsploit

// FIXME

## msfvenom

// FIXME

## hydra

// FIXME

## hashcat

// FIXME
