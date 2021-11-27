Split-Path $MyInvocation.MyCommand.Path | Push-Location

$readme_path = Get-Childitem -Path \Users -Recurse -ErrorAction SilentlyContinue -File -Include README.url | Select-Object -First 1

if (!$readme_path) {
	Exit
}

$readme = Get-Content $readme_path.Name | Select-Object -Index 1 | ForEach-Object { $_.SubString(4) }
Invoke-WebRequest -Uri $readme -Outfile readme.txt

Remove-Variable readme, readme_path

$password = "P0stM0rtem!"

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
		$confirm = Read-Host -Prompt "Remove user $user? (y/N)"

		if ($confirm -eq "y") {
			# remove them
			Remove-LocalUser -Name $user.Name
		}
	}
}

Remove-Variable machine_users, admins, users