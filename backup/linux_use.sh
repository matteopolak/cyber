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

# use the backup
/bin.bak/tar -xzf --ignore-failed-read /content.tar.gz