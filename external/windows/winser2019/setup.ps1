Install-Module AuditPolicyDSC -Force
Install-Module ComputerManagementDSC -Force
Install-Module SecurityPolicyDSC -Force

./WindowsServer2019.ps1

Set-NetConnectionProfile -NetworkCategory Private -Force
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048 -Force

winrm quickconfig
Start-DscConfiguration -Path .\WindowsServer2019  -Force -Wait