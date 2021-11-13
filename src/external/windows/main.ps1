$readme = Select-String -Path "README.desktop" -Pattern '(?<=^Exec=x-www-browser \")([^\"]+)'
Invoke-WebRequest -Uri $readme.matches.groups[1].ToString() -Outfile readme.txt

Remove-Variable readme

$password = "mortem"

$whitelist_block = Get-Content -Raw -Path "readme.txt" | Select-String -Pattern '<b>Authorized Administrators(?:.|\n)*?(?=<\/pre)';
$is_admin = $true

$admins = New-Object system.collections.arraylist
$users = New-Object system.collections.arraylist

foreach ($match in $($whitelist_block.Matches[0] -split "`r`n")) {
	if ($match -eq "<b>Authorized Users:</b>") {
		$is_admin = $false
	} elseif ($match -match "^[a-z]") {
		$username_raw = $match | Select-String -Pattern "^([a-z]+)"
		$username = $username_raw.Matches.Groups[1]

		if ($is_admin) {
			$admins.Add($username) > $null
		} else {
			$users.Add($username) > $null
		}
	}
}

Remove-Variable whitelist_block, is_admin

$machine_users = Get-LocalUser -Name * | Where-Object {$_.Enabled -eq "True"} | Select-Object Name

foreach ($user in $machine_users) {
	Write-Host $user.Name

	# if they're an admin
	if ($admins.Contains($user.Name)) {
		# make them an administrator
		Add-LocalGroupMember -Group "Administrators" -Member $user.Name

		# change their password
		Set-LocalUser -Password $password
	# if they're a normal user
	} elseif ($users.Contains($user.Name)) {
		# remove their administrator status
		Remove-LocalGroupMember -Group "Administrators" -Member $user.Name

		# change their password
		Set-LocalUser -Password $password
	# if they're not allowed on the machine
	} else {
		# remove them
		Remove-LocalUser -Name $user.Name
	}
}

Remove-Variable machine_users, admins, users

# password settings
net accounts /MINPWLEN:10
net accounts /MAXPWAGE:30
net accounts /MINPWAGE:3
net accounts /UNIQUEPW:5

# enable Windows SmartScreen
reg add “HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer” /v SmartScreenEnabled /t REG_SZ /d On

# update Windows
Import-Module PSWindowsUpdate
Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot -confirm:$false