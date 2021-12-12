#!/bin/bash

# note: the backup archive *must* be located at /content.tar.gz

# delete current files
shopt -s extglob

cd /opt
rm -rf !("CyberPatriot")

cd /root
rm -rf !("snap")

mkdir /usr.bk
mkdir /usr.bk/bin
mkdir /etc
mkdir /usr
mkdir /usr/lib

cp /usr/bin/mv /usr.bk/bin/mv

/usr.bk/bin/mv /usr /usr.bk
/usr.bk/bin/mv /boot /boot.bk
/usr.bk/bin/mv /etc /etc.bk
/usr.bk/bin/mv /home /home.bk
/usr.bk/bin/mv /lost+found /lost+found.bk
/usr.bk/bin/mv /media /media.bk
/usr.bk/bin/mv /srv /srv.bk
/usr.bk/bin/mv /var /var.bk

/usr.bk/bin/cp /etc.bk/os-release /etc/os-release
/usr.bk/bin/cp /usr.bk/lib/os-release /usr/lib/os-release

# use the backup
/bin.bk/tar -xzf --ignore-failed-read /content.tar.gz

/usr.bk/bin/cp /etc.bk/os-release /etc/os-release
/usr.bk/bin/cp /usr.bk/lib/os-release /usr/lib/os-release