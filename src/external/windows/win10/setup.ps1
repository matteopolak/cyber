install-module AuditPolicyDSC
install-module ComputerManagementDsc
install-module SecurityPolicyDsc

./Windows10.ps1

Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
winrm quickconfig
Start-DscConfiguration -Path .\Windows10  -Force -Verbose -Wait