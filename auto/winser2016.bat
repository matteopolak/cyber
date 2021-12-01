cd /D "%~dp0"

curl https://cyberpatriot.matteopolak.workers.dev
powershell "Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy Unrestricted -Force"

:: run filesystem diff script
call "../internal/windows/find-winser2016.bat"
cd /D "%~dp0"

:: run CIS-compliant script
powershell "../external/windows/winser2016/setup.ps1"
cd /D "%~dp0"

:: run CyberPatriot-specific script
powershell "../internal/windows/main.ps1"
cd /D "%~dp0"

mkdir "../results"
powershell "Get-Childitem -Recurse -Exclude ./results .. -filter *.txt | Copy-Item -Destination ../results -ErrorAction 'SilentlyContinue'"