#!/bin/bash

# note: the backup archive *must* be located at /content.tar.gz

d_IFS=$IFS;
IFS=$'\n';
USERS_INPUT_RAW=($(more $(find /home -name "README.desktop") | grep -oP "(?<=^Exec=x-www-browser \")([^\"]+)" | xargs wget -qO- | grep -Pzo "<b>Authorized Administrators(.|\n)*?(?=<\/pre)"));
is_admin=1;
IFS=' ';

USERS=();
ADMINS=();

for line in "${USERS_INPUT_RAW[@]}"; do
	if [[ "$line" =~ ^...Authorized\ Users ]]; then
		is_admin=0;
	elif [[ "$line" =~ ^[a-z]+ ]]; then
		username=$(echo $line | grep -Po "^[a-z]+");

		if [ $is_admin -eq 1 ]; then
			ADMINS+=("$username");
		else
			USERS+=("$username");
		fi
	fi
done

IFS=$d_IFS;

# delete current files
shopt -s extglob

cd /opt
rm -rf !("CyberPatriot")

cd /root
rm -rf !("snap")

cd /

echo "Creating 'source' directory in root..."
mkdir /source

echo "Copying over essential binaries to 'source'..."
cp /usr/bin/mv /source/mv
cp /usr/bin/mkdir /source/mkdir
cp /usr/bin/cp /source/cp
cp /usr/bin/tar /source/tar
cp /usr/bin/bzip2 /source/bzip2
cp /usr/bin/echo /source/echo
cp /usr/bin/gzip /source/gzip

echo "Copying linked library folders to 'source'..."
cp -r /usr/lib /source/lib
cp -r /usr/lib32 /source/lib32
cp -r /usr/lib64 /source/lib64
cp -r /usr/libx32 /source/libx32

echo "Changing symlink for libraries..."
ln -sfn /source/lib /lib
ln -sfn /source/lib32 /lib32
ln -sfn /source/lib64 /lib64
ln -sfn /source/libx32 /libx32

echo "Modifying PATH..."
LIVE_PATH=$PATH
PATH="/source"

echo "Moving all folders..."
/source/mv /usr /usr.bk
/source/mv /boot /boot.bk
/source/mv /etc /etc.bk
/source/mv /home /home.bk
/source/mv /lost+found /lost+found.bk
/source/mv /media /media.bk
/source/mv /srv /srv.bk
/source/mv /var /var.bk

echo "Making new directories..."
/source/mkdir /etc
/source/mkdir /usr
/source/mkdir /usr/lib

echo "Copying over /etc/machine-id..."
/source/cp /etc.bk/machine-id /etc/machine-id

echo "Unzipping backup content..."
/source/tar xzfk content.tar.gz
/source/mv /var.bk/cache /var/cache

export PATH=$LIVE_PATH

