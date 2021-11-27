### To start...
```bash
apt update && apt upgrade && apt full-upgrade
```

### Manual tasks
1. Open your respective CIS document(s) under the `cis` directory
2. Search for `(Manual)`
3. Complete all matched tasks

### Prohibited files
* `.mp3`, `.mov`, `.mp4`, `.avi`, `.mpg`, `.mpeg`, `.flac`, `.m4a`, `.flv`, `.ogg`, `.gif`, `.png`, `.jpg`, `.jpeg`
* How-to:
	Run the following command, replacing `ext` with the extension:
	```bash
	find / -name "*.ext" 2>/dev/null
	```

### Prohibited applications
* Hacking tools, games, malware
* Possible locations
	* `/usr/bin/*`
	* `/usr/sbin/*`
	* `/var/lib/*`
	* `/root/*`
	* `/opt/*`

### File permissions
* World-writable folders
	* `/etc/[passwd, group, shadow]`
	* `/usr/bin/*`
	* `/usr/sbin/*`
	* `/etc/cron-*`

### Other tools
* [Decode base64](https://onlineutf8tools.com/convert-base64-to-utf8)
* [Reverse string](https://codebeautify.org/reverse-string)
* [Encode/decode message from image](https://stylesuxx.github.io/steganography/)
* Ciphers
	* [Caesar](https://www.boxentriq.com/code-breaking/caesar-cipher)
	* [Mono-alphabetic substitution](https://www.guballa.de/substitution-solver)
	* [Homophonic substitution](https://www.dcode.fr/homophonic-cipher)
	* [Alphabetical substitution](https://cryptii.com/pipes/alphabetical-substitution)