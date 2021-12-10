#!/bin/bash

# run filesystem diff script
bash ../internal/linux/find.sh

# run CIS-compliant hardening script
bash ../external/linux/ubu16/setup.sh

# run CyberPatriot-specific script
bash ../internal/ubuntu/main.sh

# make a directory to put results
mkdir ../results

# all results use the `.txt` suffix, so it's
# easy to move them all over at once
find .. -name \*.txt -exec mv {} ../results \;

# re-install lightdm, the GUI
apt-get install -y lightdm

# unlock user's account
usermod -U $(whoami)