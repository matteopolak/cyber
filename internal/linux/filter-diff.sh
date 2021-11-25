#!/bin/bash

cat diff.txt | grep -vP "^(/proc/\d+|/proc/(tty|sys)|/sys/(kernel|module)|/var/tmp|/var/lib/snapd|/var/log/journal|/var/lib/(polkit-1|NetworkManager|gdm3|AccountsService)|/var/cache|/tmp|/sys/(fs|devices)|/run/(user|udev|systemd|speech-dispatcher|gdm3|cups|sudo)|/root/snap|/snap/core18|/dev/disk|/etc/(polkit-1|ansible|aide)|/home/\w+/(\.config|\.local|\.mozilla)|/usr/lib/(python\d(\.\d)?)|firmware|git-core|postfix|ruby|systemd|tiger|x86_64-linux-gnu)(/|$)|.*(vm(ware|block)|\.cache)(/|$)" > diff-filter.txt