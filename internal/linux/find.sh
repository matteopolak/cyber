# create a new <distro>.tar.gz with the following commands:
#
# find / 2>/dev/null > default.txt
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
tar -xzf "$TYPE.tar.gz"

# `default.txt` contains base files
# -13 = print lines only present in second file
comm -13 default.txt tree.txt > diff.txt;

# `diff.txt` contains all file paths and files that are not
# present in a default installation of Ubuntu 20.04 or Debian 10