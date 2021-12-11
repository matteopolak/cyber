#!/bin/bash

# run filesystem diff script
bash ../internal/linux/find.sh

# run CIS-compliant hardening script
bash ../external/linux/debian/setup.sh

# run CyberPatriot-specific script
# this one mostly works on Debian still
bash ../internal/ubuntu/main.sh

# make a directory to put results
mkdir ../results

# all results use the `.txt` suffix, so it's
# easy to move them all over at once
find .. -name \*.txt -exec mv {} ../results \;

# re-install gdm3, the GUI and some dependencies
apt-get purge gdm3 -y
apt-get install lightdm lxsession -y

# disable Alsa Restore service (hangs startup)
systemctl mask alsa-restore.service alsa-store.service

# unlock user's account
usermod -U $(whoami)

# duplicity --no-encryption --full-if-older-than=1s / file:///backup