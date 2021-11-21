#!/bin/bash

# run filesystem diff script
bash ../internal/linux/find.sh

# run CyberPatriot-specific script
bash ../internal/ubuntu/main.sh

# run CIS-compliant hardening script
bash ../external/linux/ubu20/setup.sh

# make a directory to put results
mkdir ../results

# all results use the `.txt` suffix, so it's
# easy to move them all over at once
mv ../**/*.txt ../results/