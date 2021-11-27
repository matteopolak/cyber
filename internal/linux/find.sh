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

echo "Comparing against files for: ${TYPE}";

# ensure `coreutils` is installed so we can use the `comm` command
apt install coreutils parallel -y;

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

bash ./filter-diff.sh default.txt > default-filter.txt;

# `default.txt` contains base files
# -13 = print lines only present in second file
comm -13 default-stripped.txt tree.txt > diff.txt;

function check {
	local line=$1;

	# capture after first @
	local path=${line#*@};

	# capture until $path
	local permission="${line%"${path}"}";
	local local_permission=$(stat -c "%a" "${path}" 2>/dev/null);

	local permission=${permission::-1};

	# if the local permission isn't empty and is not equal to default
	if [[ ! -z $local_permission && $local_permission -ne $permission ]]; then
		echo "${permission} -> ${local_permission} @ ${path}" >> diff-permissions.txt;
	fi
}

for line in $(tr ' ' '@' < default-filter.txt); do
	check "${line}";
done

# rm tree.txt default.txt default-stripped.txt default-filter;

# filter out the `diff.txt` file to remove useless data
bash ./filter-diff.sh diff.txt > diff-filter.txt;

# `diff.txt` contains all file paths and files that are not
# present in a default installation of Ubuntu 20.04 or Debian 10