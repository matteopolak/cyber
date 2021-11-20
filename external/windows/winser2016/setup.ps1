[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Install-Module AuditPolicyDSC -Force
Install-Module ComputerManagementDSC -Force
Install-Module SecurityPolicyDSC -Force

./WindowsServer2016.ps1

Set-NetConnectionProfile -NetworkCategory Private
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048 -Force

winrm quickconfig
Start-DscConfiguration -Path .\WindowsServer2016  -Force -Wait