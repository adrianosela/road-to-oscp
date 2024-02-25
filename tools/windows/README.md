# Windows (Tools)

- [CertUtil.exe](#cerutil.exe): an http / file-download client built into windows
- [WinPEAS](#winpeas): privilege escalation vector detection


## certutil.exe

An http / file-download client built into windows ([docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)).

Usage:

```
certutil.exe -f ${URL} ${OUTPUT_FILENAME}
```

## WinPEAS

A privilege escalation vector detection script for Windows ([docs](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)) ([releases](https://github.com/carlospolop/PEASS-ng/releases)).

Usage: (just invoke the binary)

```
winpeas.exe
```