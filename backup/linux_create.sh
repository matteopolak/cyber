#!/bin/bash

# create backup folder
mkdir /backup

# create a backup
tar --exclude='/proc' --exclude='/sys' --exclude='/tmp' --exclude='/backup' --exclude='/run' --exclude='/dev' --exclude='/snap' --exclude='/mnt' --exclude='/home' --exclude='/var/cache' --ignore-failed-read -zcf /backup/content.tar.gz /