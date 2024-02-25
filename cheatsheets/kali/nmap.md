# nmap cheatsheet

Enumerate listening ports on target

```
nmap -Pn -T4 -v -p- ${TARGET} -oN ${OUTPUT_LOG_FILE}
```

Get info on specific ports including script scanning (`-sC`) and version detection (`-sV`)

```
nmap -Pn -T4 -p ${COMMA_SEPARATED_PORTS} -sCV ${TARGET} -oN ${OUTPUT_LOG_FILE}
```

Get all available info on specific ports including the above + OS detection and traceroute

```
nmap -Pn -T4 -p ${COMMA_SEPARATED_PORTS} -A ${TARGET} -oN ${OUTPUT_LOG_FILE}
```

