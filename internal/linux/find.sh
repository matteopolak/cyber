#!/bin/bash

# create a new <distro>.tar.gz with the following commands:
#
# find / -printf "%m %p\n" 2>/dev/null > default.txt
# sort -o default.txt{,}
# tar -czf distro.tar.gz default.txt

# move to script directory
cd "$(dirname "$0")"

TYPE="debian";

if [[ $(uname -a) = *Ubuntu* ]]; then
	TYPE="ubuntu";
fi

echo "Using template '${TYPE}'";

# ensure `coreutils` is installed so we can use the `comm` command
apt install coreutils tree -y;

# pipe errors to `/dev/null`, as `/run/user/1000/gvfs` is restricted
# to the owner only, so we can't read it (and don't need to)
find / 2>/dev/null > tree.txt;

# sort the file by lexical order so `comm` is faster
# this uses bash brace expansion to avoid repeating filename
sort -o tree.txt{,};

# unzip `<type>.tar.gz`
tar -xzf "$TYPE.tar.gz";

# remove the file permissions from each line
sed 's/[^ ]* //' default.txt > default-stripped.txt;
sort -o default-stripped.txt{,};

# `default.txt` contains base files
# -13 = print lines only present in second file
comm -13 default-stripped.txt tree.txt > diff.txt;

# create a file with file permissions on each line
xargs -0 stat -c "%a" < <(tr \\n \\0 <default-stripped.txt) 1>permissions.txt 2>&1;

# merge the file permissions with the file names into one file
paste -d ' ' permissions.txt default-stripped.txt > local.txt;

# sort the file
sort -o local.txt{,};

# get all lines that are unique to file 1
comm -23 default.txt local.txt > default-samepath.txt;

# remove permissions from file
sed 's/[^ ]* //' default-samepath.txt > default-samepath-stripped.txt;

# remove paths from file
sed 's/\s.*$//' default-samepath.txt > default-samepath-permissions.txt;

# create another file with file permissions on each line, this time only on ones unique to default
xargs -0 stat -c "%a" < <(tr \\n \\0 <default-samepath-stripped.txt) 1> permissions-samepath.txt 2>&1;

# merge local permissions with paths
paste -d ' ' permissions-samepath.txt default-samepath-stripped.txt > local-samepath.txt;

# merge local permissions & paths with default permissions
paste -d ' ' default-samepath-permissions.txt local-samepath.txt > diff-permissions-raw.txt;

# remove stat errors from files that don't exist on the system
grep -v " stat:" < diff-permissions-raw.txt > diff-permissions.txt;

# cleanup
rm tree.txt default.txt default-stripped.txt local.txt default-samepath.txt default-samepath-stripped.txt default-samepath-permissions.txt permissions-samepath.txt local-samepath.txt diff-permissions-raw.txt permissions.txt;

# filter out the `diff.txt` file to remove useless data
bash ./filter-diff.sh diff.txt > diff-filter.txt;
bash ./filter-diff.sh diff-permissions.txt > diff-permissions-filter.txt;

tree --fromfile diff-filter.txt > diff-filter-tree.txt;

# `diff.txt` contains all file paths and files that are not
# present in a default installation of Ubuntu 20.04 or Debian 10

# `diff-permissions.txt` contains all file paths and permissions that are not
# identical in a default installation of Ubuntu 20.04 or Debian 10
