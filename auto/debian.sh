#!/bin/bash

# run filesystem diff script
bash ../internal/linux/find.sh

# run CyberPatriot-specific script
# this one mostly works on Debian still
# bash ../internal/ubuntu/main.sh

# run CIS-compliant hardening script
bash ../external/linux/debian/setup.sh

# make a directory to put results
mkdir ../results

# all results use the `.txt` suffix, so it's
# easy to move them all over at once
find .. -name \*.txt -exec mv {} ../results \;

# re-install gdm3, the GUI
apt-get install -y gdm3