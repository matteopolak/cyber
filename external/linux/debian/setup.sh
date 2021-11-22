#!/bin/bash

# move to script directory
cd "$(dirname "$0")"

# Install dependencies
apt install git -y

mkdir /etc/postmortem
cd /etc/postmortem

git clone https://github.com/ovh/debian-cis.git
cd debian-cis

cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='$(pwd)'#" /etc/default/cis-hardening

bash bin/hardening.sh --apply --allow-unsupported-distribution