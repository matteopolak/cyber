install-module AuditPolicyDSC
install-module ComputerManagementDsc
install-module SecurityPolicyDsc

./WindowsServer2016.ps1

Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
winrm quickconfig
Start-DscConfiguration -Path .\WindowsServer2016  -Force -Verbose -Wait