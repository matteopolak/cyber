#!/bin/bash

# Install dependencies
apt install ansible git -y

mkdir /etc/postmortem
cd /etc/postmortem

git clone https://github.com/ovh/debian-cis.git
cd debian-cis

cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='$(pwd)'#" /etc/default/cis-hardening

source bin/hardening.sh --apply --allow-unsupported-distribution

mkdir /etc/ansible
cd /etc/ansible

echo '- src: https://github.com/matteopolak/debian10-cis.git' >> /etc/ansible/requirements.yml

ansible-galaxy install -p roles -r /etc/ansible/requirements.yml