### Prohibited files
* `.mp3`, `.mov`, `.mp4`, `.avi`, `.mpg`, `.mpeg`, `.flac`, `.m4a`, `.flv`, `.ogg`, `.gif`, `.png`, `.jpg`, `.jpeg`
* How-to:
	* Run the following powershell command, replacing `ext` with the extension:
	```powershell
	Get-ChildItem -Path \Users -Filter *.ext -Recurse -File -ErrorAction 'SilentlyContinue' | ForEach-Object { $_.FullName }
	```

### Prohibited applications
* Hacking tools, games, malware
* Possible locations
	* `C:/Users/*`
	* `C:/Program Files/*`,
	* `C:/Program Files (x86)/*`

### File permissions
* World-writable folders
	* `C:/Windows`
	* `C:/Program Files`
	* `C:/Program Files (x86)`

### Other tools
* [Decode base64](https://onlineutf8tools.com/convert-base64-to-utf8)
* [Reverse string](https://codebeautify.org/reverse-string)
* [Encode/decode message from image](https://stylesuxx.github.io/steganography/)
* Ciphers
	* [Caesar](https://www.boxentriq.com/code-breaking/caesar-cipher)
	* [Mono-alphabetic substitution](https://www.guballa.de/substitution-solver)
	* [Homophonic substitution](https://www.dcode.fr/homophonic-cipher)
	* [Alphabetical substitution](https://cryptii.com/pipes/alphabetical-substitution)