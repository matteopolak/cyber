Install-Module AuditPolicyDSC
Install-Module ComputerManagementDSC
Install-Module SecurityPolicyDSC

./WindowsServer2019.ps1

Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
winrm quickconfig
Start-DscConfiguration -Path .\WindowsServer2019  -Force -Verbose -Wait