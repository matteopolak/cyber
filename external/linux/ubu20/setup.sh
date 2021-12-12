#!/bin/bash

# move to script directory
cd "$(dirname "$0")"

# disable sleeping
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# add ansible repo so we can use version 2.9+
add-apt-repository --yes --update ppa:ansible/ansible

# Install dependencies
apt install ansible git openssh-server systemd-timesyncd -y

# create config files
touch /etc/rsyslog.d/50-default.conf
touch /etc/ssh/sshd_config

mkdir /etc/ansible
cd /etc/ansible

# set up configuration of roles
cat > /etc/ansible/requirements.yml << EOF
- src: https://github.com/matteopolak/ubuntu2004_cis.git
EOF

# install all roles
ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

# set up configuration
cat > /etc/ansible/harden.yml << EOF
- name: Harden Server
  hosts: localhost
  connection: local
  become: yes
  ignore_errors: yes

  roles:
    - ubuntu2004_cis
EOF

# start all scripts
ansible-playbook /etc/ansible/harden.yml

# re-install 'gdm3'
apt install gdm3 -y

# unlock main user
usermod -U $(whoami)

# set user password
usermod -p $(whoami) root