:: run filesystem diff script
call "../internal/windows/find-winser2016.bat"

:: run CIS-compliant script
powershell "../external/windows/winser2019/setup.ps1"

:: run CyberPatriot-specific script
powershell "../internal/windows/main.ps1"

mkdir ../results
powershell "Get-Childitem -Recurse -Exclude ./results .. -filter *.txt | Copy-Item -Destination ../results -ErrorAction 'SilentlyContinue'"