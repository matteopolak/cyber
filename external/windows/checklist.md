### To start...
* Start all Windows updates and Service Packs

### Manual tasks
1. Open your respective CIS document(s) under the `cis` directory
2. Search for `(Manual)`
3. Complete all matched tasks

### Prohibited files
* `.mp3`, `.mov`, `.mp4`, `.avi`, `.mpg`, `.mpeg`, `.flac`, `.m4a`, `.flv`, `.ogg`, `.gif`, `.png`, `.jpg`, `.jpeg`
* How-to:
	* Run the following powershell command, replacing `ext` with the extension:
	```powershell
	Get-ChildItem -Path \Users -Filter *.ext -Recurse -File -ErrorAction 'SilentlyContinue' | ForEach-Object { $_.FullName }
	```

### File permissions
* World-writable folders
	* `C:/Windows`
	* `C:/Program Files`
	* `C:/Program Files (x86)`

### Disable services
* Telnet
* FTP
* IIS

### Startup programs
* Disable unnecessary programs on startup (`Startup Apps`)

### Prohibited applications
* Hacking tools, games, malware
* Possible locations
	* `C:/Users/*`
	* `C:/Program Files/*`,
	* `C:/Program Files (x86)/*`
* History of removed tools:
	* Farbar Recovery Scan Tool
	* Zed Attack Proxy
	* Wireshark
	* Progress Telerik Fiddler Web Debugger
	* K-Lite Codec Pack
	* Tini backdoor

### Other checks
* Event Viewer logs
* Task Manager resource usage & performance
* View open ports
* Run an anti-virus

### Other tools
* [Decode base64](https://onlineutf8tools.com/convert-base64-to-utf8)
* [Reverse string](https://codebeautify.org/reverse-string)
* [Encode/decode message from image](https://stylesuxx.github.io/steganography/)
* Ciphers
	* [Caesar](https://www.boxentriq.com/code-breaking/caesar-cipher)
	* [Mono-alphabetic substitution](https://www.guballa.de/substitution-solver)
	* [Homophonic substitution](https://www.dcode.fr/homophonic-cipher)
	* [Alphabetical substitution](https://cryptii.com/pipes/alphabetical-substitution)