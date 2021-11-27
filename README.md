## Disclaimer
This repository is made solely for the **Post Mortem** [CyberPatriot](https://www.uscyberpatriot.org/) team. **You are not allowed to use any of these tools for competing in the CyberPatriot competition to any degree. Usage of these scripts will result in immediate disqualification.**

| Folder | Description |
| --- | --- |
| `cis` | <u>**C**</u>entre for <u>**I**</u>nternet <u>**S**</u>ecurity-compliant documents for hardening multiple operating systems |
| `docs` | Documentation and tools for general use |
| `external` | Scripts not made by the Post Mortem team |
| `history` | An aggregation of data collected from previous competition rounds |
| `internal` | Scripts made by the Post Mortem team |

## Linux-based
Run the following command to fix line endings:
```bash
$ shopt -s globstar
$ dos2unix ./**/*.sh
```

Then run one of these commands depending on your distribution:

### Ubuntu
* Ubuntu 16.04
	* `sudo bash ./auto/ubu16.sh`
	* [`external/linux/ubu16`](./external/linux/ubu16)
* Ubuntu 18.04
	* `sudo bash ./auto/ubu18.sh`
	* [`external/linux/ubu18`](./external/linux/ubu18)
* Ubuntu 20.04
	* `sudo bash ./auto/ubu20.sh`
	* [`external/linux/ubu20`](./external/linux/ubu20)
* [`internal/ubuntu`](./internal/ubuntu)
* [`internal/linux`](./internal/linux)
* [`cis/ubuntu`](./cis/ubuntu)

### Debian
* Debian 9
	* `sudo bash ./auto/debian.sh`
* Debian 10
	* `sudo bash ./auto/debian.sh`
* [`internal/linux`](./internal/linux)
* [`external/linux/debian`](./external/linux/debian)
* [`cis/debian`](./cis/debian)

## Windows-based
Run the following command to enable PowerShell scripts:
```powershell
> Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force
```

Then run one of these commands depending on your distribution:

### Windows 10
* `./auto/win10.bat`
* [`internal/windows`](./internal/windows)
* [`external/windows/win10`](./external/windows/win10)
* [`cis/win10`](./cis/win10)

### Windows Server 2019
* `./auto/winser2019.bat`
* [`internal/windows`](./internal/windows)
* [`external/windows/winser2019`](./external/windows/winser2019)
* [`cis/winser2019`](./cis/winser2019)

### Windows Server 2016
* `./auto/winser2016.bat`
* [`internal/windows`](./internal/windows)
* [`external/windows/winser2016`](./external/windows/winser2016)
* [`cis/winser2016`](./cis/winser2016)