### Setup
* Open Command Prompt (`cmd.exe`)
* Windows 10
	* `find-win10.bat`
* Windows Server 2016
	* `find-winser2016.bat`
* Windows Server 2019
	* `find-winser2019.bat`

### Updating archives
```cmd
> where /R \ * > default.txt
> sort default.txt /o default.txt
> tar -czf <release>.tar.gz default.txt
```