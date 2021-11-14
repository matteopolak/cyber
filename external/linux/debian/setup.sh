#!/bin/bash

d_IFS=$IFS;
IFS=$'\n';
USERS_INPUT_RAW=($(more README.desktop | grep -oP "(?<=^Exec=x-www-browser \")([^\"]+)" | xargs wget -qO- | grep -Pzo "<b>Authorized Administrators(.|\n)*?(?=<\/pre)"));
is_admin=1;
IFS=' ';

USERS=();

for line in "${USERS_INPUT_RAW[@]}"; do
	if [[ "$line" =~ ^...Authorized\ Users ]]; then
		is_admin=0;
	elif [[ "$line" =~ ^[a-z]+ ]]; then
		username=$(echo $line | grep -Po "^[a-z]+");

		USERS+=("$username");
	fi
done

IFS=$d_IFS;

# Install dependencies
apt install ansible git -y

mkdir /etc/postmortem
cd /etc/postmortem

git clone https://github.com/ovh/debian-cis.git
cd debian-cis

cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='$(pwd)'#" /etc/default/cis-hardening

bash bin/hardening.sh --apply --allow-unsupported-distribution

mkdir /etc/ansible
cd /etc/ansible

echo '- src: https://github.com/matteopolak/debian10-cis.git' >> /etc/ansible/requirements.yml

ansible-galaxy install -p roles -r /etc/ansible/requirements.yml

cat > /etc/ansible/harden.yml << EOF
- name: Harden Server
  IPv6_is_enabled: no
  enable_firewall: yes
  firewall_type: ufw
  list_of_rules_to_allow:
    - { desc: "ssh", rule: "tcp dport ssh accept" }
    - { desc: "ping", rule: "ip protocol icmp accept" }
  grub_backlog_limit: 8192
  max_log_file: 10
  #max_log_file_action: keep_logs
  max_log_file_action: rotate
  admin_space_left_action: email
  space_left_action: email
  action_mail_acct: root
  backlog_limit: "8192"
  architecture: "x86_64"
  remoteSyslog:
    enable: True
    host: syslogserver
    port: 514
    protocol: tcp
  logrotate_policy: "daily"
  allowed_users: None
  allowed_groups: sys root sshadmins
  deny_users: None
  deny_groups: None
  pass_expire_in_days: 310
  pass_warn_age: 7
  pass_min_days: 1
  list_of_os_users:
    - users
  account_inactive: 30
  shell_timeout_sec: 900
  withoutOwnerFileDirOwner: root
  withoutGroupFilesDirGroup: root
EOF

ansible-playbook -i host /etc/ansible/harden.yml --list-tags