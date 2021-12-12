#!/bin/bash

# create backup folder
mkdir /backup

# create a backup
tar --exclude='/swapfile' --exclude='/boot' --exclude='/proc' --exclude='/sys' --exclude='/tmp' --exclude='/backup' --exclude='/run' --exclude='/dev' --exclude='/snap' --exclude='/mnt' --ignore-failed-read -zcf /backup/content.tar.gz /