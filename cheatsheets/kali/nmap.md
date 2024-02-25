# nmap cheatsheet

Enumerate target:

```
nmap -Pn -T4 -v -p- ${TARGET} -oN ${OUTPUT_LOG_FILE}
```

Get info on specific ports:

```
nmap -Pn -T4 -p${COMMA_SEPARATED_PORTS} -sCV ${TARGET} -oN ${OUTPUT_LOG_FILE}
```
