#!/bin/bash

# Install dependencies
apt install ansible -y

mkdir /etc/ansible
cd /etc/ansible

echo '- src: https://github.com/matteopolak/ubuntu1604_cis.git' >> /etc/ansible/requirements.yml;

ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

cat > /etc/ansible/harden.yml << EOF
- name: Harden Server
  hosts: localhost
  connection: local
  become: yes

  roles:
    - ubuntu1604_cis
EOF

ansible-playbook /etc/ansible/harden.yml