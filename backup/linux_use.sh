#!/bin/bash

# note: the backup archive *must* be located at /content.tar.gz

# delete current files
shopt -s extglob

cd /opt
rm -rf !("CyberPatriot")

cd /root
rm -rf !("snap")

mv /usr /usr.bk
/usr.bk/mv /boot /boot.bk
/usr.bk/mv /etc /etc.bk
/usr.bk/mv /home /home.bk
/usr.bk/mv /lost+found /lost+found.bk
/usr.bk/mv /media /media.bk
/usr.bk/mv /srv /srv.bk
/usr.bk/mv /var /var.bk

mkdir /etc
mkdir /usr
mkdir /usr/lib

cp /etc.bk/os-release /etc/os-release
cp /usr.bk/lib/os-release /usr/lib/os-release

# use the backup
/bin.bak/tar -xzf --ignore-failed-read /content.tar.gz

cp /etc.bk/os-release /etc/os-release
cp /usr.bk/lib/os-release /usr/lib/os-release