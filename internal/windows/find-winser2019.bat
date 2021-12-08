:: create a new winser2019.tar.gz with the following commands:
::
:: where /R \ * > default.txt
:: sort default.txt /o default.txt
:: tar -czf winser2019.tar.gz default.txt

cd /D "%~dp0"

:: pipe all file names to `tree.txt`
where /R \ * > tree.txt

:: sort the file by lexical order so `comm` is faster
:: this uses bash brace expansion to avoid repeating filename
sort tree.txt /o tree.txt

:: unzip `winser2019.tar.gz`
tar -xzf winser2019.tar.gz

:: `default.txt` contains base files
:: -13 = print lines only present in second file
"./bin/comm.exe" -13 default.txt tree.txt > diff.txt

:: `diff.txt` contains all file paths and files that are not
:: present in a default installation of Windows Server 2019

:: filter out the `diff.txt` file to remove useless data
./filter-diff.bat
