### Easy
* Read the README located at **~/Desktop/README.desktop**
* Complete forensics questions that rely on machine state
* Run the **main.sh** script
* Create any required users
* Verify package integrity with `dpkg --verify`

### Medium
* Hidden users in **/etc/lightdm/users.conf**
* Bad sources in **/etc/apt/sources.list**
* Redirects in **/etc/hosts**
* Malicious cron jobs with `crontab -e`
* Suspicious services with `apt install bum`
* Sudoer permissions with `visudo`

### Advanced
* Secure ports
	0. Safe ports: 22, 53, 631, 35509
	1. `ss -ln | grep tcp`
	2. Search for port process with `lsof -i <port>`
	3. Remove if it's unsafe

### Maintenance
* Run `service lightdm restart` to apply LightDM changes

### Out of ideas?
* Read the appropriate CIS benchmark in the [cis folder](../../cis)
* Check out **runthough.md**

### Stuff to search
* `/etc/sudoers.d/README`
* `visudo`