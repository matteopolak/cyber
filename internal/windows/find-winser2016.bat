:: create a new winser2016.tar.gz with the following commands:
::
:: where /R \ * > default.txt
:: sort default.txt /o default.txt
:: tar -czf winser2016.tar.gz default.txt

cd /D "%~dp0"

:: pipe all file names to `tree.txt`
where /R \ * > tree.txt

:: sort the file by lexical order so `comm` is faster
:: this uses bash brace expansion to avoid repeating filename
sort tree.txt /o tree.txt

:: unzip `winser2016.tar.gz` (`tar` is not installed by default on Windows Server 2016)
"./bin/tar.exe" -xzf winser2016.tar.gz

:: `default.txt` contains base files
:: -13 = print lines only present in second file
"./bin/comm.exe" -13 default.txt tree.txt > diff.txt

:: `diff.txt` contains all file paths and files that are not
:: present in a default installation of Windows Server 2016

:: filter out the `diff.txt` file to remove useless data
./filter-diff.bat
