#!/bin/bash

back=$(pwd);

# run filesystem diff script
source ../internal/linux/find.sh
cd "$back";

# run CyberPatriot-specific script
# this one mostly works on Debian still
source ../internal/ubuntu/main.sh
cd "$back";

# run CIS-compliant hardening script
source ../external/linux/debian/setup.sh
cd "$back";

# make a directory to put results
mkdir ../results

# all results use the `.txt` suffix, so it's
# easy to move them all over at once
mv ../**/*.txt ../results/