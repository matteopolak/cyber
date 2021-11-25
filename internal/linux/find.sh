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
apt install coreutils -y;

# pipe errors to `/dev/null`, as `/run/user/1000/gvfs` is restricted
# to the owner only, so we can't read it (and don't need to)
find / 2>/dev/null > tree.txt;

# sort the file by lexical order so `comm` is faster
# this uses bash brace expansion to avoid repeating filename
sort -o tree.txt{,};

# unzip `<type>.tar.gz`
tar -xzf "$TYPE.tar.gz";

# remove first 5 characters from each line (the file permissions)
sed 's/[^ ]* //' > default_stripped.txt;

# `default.txt` contains base files
# -13 = print lines only present in second file
comm -13 default_stripped.txt tree.txt > diff.txt;
common_entries=($(comm -12 default_stripped.txt tree.txt));

# create an associative array
declare -A file_permissions;

# map file path to its permission
while read line; do
	# capture after first space
	path=${line#* };
	# capture until $path
	permission"=${line%"${path}"}";

	# map path to permission
	file_permissions["${path}"]=${permission::-1};
done < default.txt

for entry in "${common_entries[@]}"; do
	local_permission=$(stat -c "%a" "${entry}");
	default_permission=${file_permissions["${entry}"]};

	if [[ local_permission -ne default_permission ]]; then
		echo "${default_permission} -> ${local_permission} @ ${entry}" >> diff-permissions.txt;
	fi
done

# filter out the `diff.txt` file to remove useless data
bash ./filter-diff.sh;

# `diff.txt` contains all file paths and files that are not
# present in a default installation of Ubuntu 20.04 or Debian 10