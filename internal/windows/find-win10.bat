rem create a new windows.tar.gz with the following commands:
rem
rem where /R \ * > default.txt
rem sort default.txt /o default.txt
rem tar -czf distro.tar.gz default.txt

rem ignore errors with 'SilentlyContinue'
where /R \ * > tree.txt;

rem sort the file by lexical order so `comm` is faster
rem this uses bash brace expansion to avoid repeating filename
sort tree.txt /o tree.txt;

rem unzip `win10.tar.gz`
tar -xzf win10.tar.gz

rem `default.txt` contains base files
rem -13 = print lines only present in second file
"./bin/comm.exe" -13 default.txt tree.txt > diff.txt;

rem `diff.txt` contains all file paths and files that are not
rem present in a default installation of Windows 10