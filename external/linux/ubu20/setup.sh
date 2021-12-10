#!/bin/bash

# move to script directory
cd "$(dirname "$0")"

# add ansible repo so we can use version 2.9+
add-apt-repository --yes --update ppa:ansible/ansible

# Install dependencies
apt install ansible git -y

mkdir /etc/ansible
cd /etc/ansible

echo << EOF
- src: https://github.com/matteopolak/ubuntu2004_cis.git
- src: https://github.com/alivx/CIS-Ubuntu-20.04-Ansible
- src: https://github.com/ansible-lockdown/UBUNTU20-CIS
EOF >> /etc/ansible/requirements.yml;

ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

cat > /etc/ansible/harden.yml << EOF
- name: Harden Server
  hosts: localhost
  connection: local
  become: yes

  roles:
    - ubuntu2004_cis

- name: Harden Server
  hosts: localhost
  connection: local
  become: yes

  roles:
    - UBUNTU20-CIS

- name: Harden Server
  hosts: localhost
  connection: local
  become: yes
	allowed_users: root cool

  roles:
    - CIS-Ubuntu-20.04-Ansible
EOF

ansible-playbook /etc/ansible/harden.yml