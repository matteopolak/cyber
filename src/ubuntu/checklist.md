### Easy
* Read the README located at **~/Desktop/README.desktop**
* Complete forensics questions that rely on machine state
* Run the **main.sh** script
* Create any required users

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
* Check out **runthough.md**

* Leverage **strace** to view system calls of the CCSClient process. Every 5 seconds, CCSClient runs a bunch of commands to see which points you have received. By looking at system calls, you can follow where they go and find points fairly easily. **This is not against the rules, even though it seems sketchy. Just don't stop the CCSClient process or it will stop running. If you accidentally stop it, you can restart it with `sudo /opt/CyberPatriot/CCSClient`**.
	1. Search for the CCSClient process with `ps -aux | grep CCSClient -m 1`
	2. Inspect the running process with `strace -p -s 128 <pid>`
	3. If you want something more automatic, run `inspect.sh` :)

* Use **gcore** to dump the memory of the CCSClient process. **It contains answers to the entire competition, just look closely!**