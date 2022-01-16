#!/bin/bash

# move to script directory
cd "$(dirname "$0")"

VERSION="1-UBUNTU";

GRUB_PASSWORD="grubpassword";
USER_PASSWORD="P0stM0rtem!";

SYSLOG_BASEDIR="/etc/syslog-ng";
LOG_FILE="log_file.txt";
APPARMOR_FILE="apparmor.txt";

DUPLICATES_FILE="dupes.txt";
PASSWORD_FILE="password.txt";
DOWNLOADS_FILE="downloads.txt";

FNRET=0;

function yes_no {
	local QUESTION=$1;
	local RESPONSE;
	local RESULT=0;

	logger "$QUESTION (Y/n): " 2;
	read -n 1 -r RESPONSE;

	if [[ "$RESPONSE" = "" ]]; then
		RESULT=1;
	elif [[ ${RESPONSE,,} = "y" ]]; then
		RESULT=1;
		echo "";
	else
		echo "";
	fi

	FNRET=$RESULT;
}

function get_response {
	local QUESTION=$1;
	local RESPONSE;
	local RESULT=0;

	logger "$QUESTION " 2;
	read -r RESPONSE;

	FNRET=$RESPONSE;
}

function update_time {
	NOW="[$(date +"%T")]";
}

function logger {
	local MESSAGE="$1";
	local NEW_LINE="\r";

	if [[ $2 -eq 0 ]]; then
		NEW_LINE="\n";
	elif [[ $2 -eq 2 ]]; then
		NEW_LINE="";
	fi

	update_time;
	printf "\33[2K $NOW $MESSAGE$NEW_LINE";
}

function random_password {
	# local PASSWORD_LENGTH=$1;
	# local PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w "$PASSWORD_LENGTH" | head -n 1);

	# FNRET=$PASSWORD;

	FNRET=$USER_PASSWORD;
}

function backup_file {
	local FILE=$1;
	
	if [[ ! -f $FILE ]]; then
		FNRET=1;
	else
		local TARGET=$(echo "$FILE" | sed -s -e 's/\//./g' -e 's/^.//' -e "s/$/.$(date +%F-%H_%M_%S)/" );

		cp -a "$FILE" "$BACKUPDIR/$TARGET";
		FNRET=0;
	fi
}

function is_nx_supported_and_enabled {
	if grep -q ' nx ' /proc/cpuinfo; then
		if $SUDO_CMD grep -qi 'noexec=off' /proc/cmdline; then
			FNRET=1;
		else
			FNRET=0;
		fi
	else
		FNRET=1;
	fi
}

function has_sysctl_param_expected_result {
	local SYSCTL_PARAM=$1;
	local EXP_RESULT=$2;

	if [[ "$(sysctl "$SYSCTL_PARAM" 2>/dev/null)" = "$SYSCTL_PARAM = $EXP_RESULT" ]]; then
		FNRET=0;
	elif [[ $? -eq 255 ]]; then
		FNRET=255;
	else
		FNRET=1;
	fi
}

function sysctl_set_param {
	local SYSCTL_PARAM=$1;
	local VALUE=$2;

	if [[ "$(sysctl -w "$SYSCTL_PARAM"="$VALUE" 2>/dev/null)" = "$SYSCTL_PARAM = $VALUE" ]]; then
		FNRET=0;
	elif [[ $? -eq 255 ]]; then
		FNRET=255;
	else
		FNRET=1;
	fi
}

function dmesg_does_pattern_exist {
	local PATTERN=$1;

	if $(dmesg | grep -qE "$PATTERN"); then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function check_file_existance {
	local FILE=$1;

	if [[ -e $FILE ]]; then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function file_has_correct_ownership {
	local FILE=$1;
	local USER=$2;
	local GROUP=$3;
	local USERID=$(id -u "$USER");
	local GROUPID=$(getent group "$GROUP" | cut -d: -f3);

	if [[ "$(stat -c "%u %g" "$FILE")" = "$USERID $GROUPID" ]]; then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function file_has_correct_permissions {
	local FILE=$1;
	local PERMISSIONS=$2;
	
	if [[ $(stat -L -c "%a" "$1") = "$PERMISSIONS" ]]; then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function file_does_pattern_exist {
	local FILE=$1;
	local PATTERN=$2;

	if [[ -r "$FILE" ]]; then
		if $(grep -qE -- "$PATTERN" "$FILE"); then
			FNRET=0;
		else
			FNRET=1;
		fi
	else
		FNRET=2;
	fi

}

function append_to_file {
	local FILE=$1;
	local LINE=$2;

	backup_file "$FILE";
	echo "$LINE" >> "$FILE";
}
	
function file_addline_before_pattern {
	local FILE=$1;
	local LINE=$2;
	local PATTERN=$3;

	backup_file "$FILE";
	PATTERN=$(sed 's@/@\\\/@g' <<< "$PATTERN");
	sed -i "/$PATTERN/i $LINE" "$FILE";
	FNRET=0;
}

function replace_in_file {
	local FILE=$1;
	local SOURCE=$2;
	local DESTINATION=$3;

	backup_file "$FILE";
	SOURCE=$(sed 's@/@\\\/@g' <<< "$SOURCE");
	sed -i "s/$SOURCE/$DESTINATION/g" "$FILE";
	FNRET=0;
}

function delete_line_in_file {
	local FILE=$1;
	local PATTERN=$2;

	backup_file "$FILE";
	PATTERN=$(sed 's@/@\\\/@g' <<< "$PATTERN");
	sed -i "/$PATTERN/d" "$FILE";
	FNRET=0;
}

function is_service_enabled {
	local SERVICE=$1;

	if [[ $(find /etc/rc?.d/ -name "S*$SERVICE" -print | wc -l) -gt 0 ]]; then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function is_kernel_option_enabled {
	local KERNEL_OPTION="$1";
	local MODULE_NAME="";

	if [[ $# -ge 2 ]]; then
		MODULE_NAME="$2";
	fi

	if [[ -r "/proc/config.gz" ]]; then
		RESULT=$(zgrep "^$KERNEL_OPTION=" /proc/config.gz) || :;
	elif [[ -r "/boot/config-$(uname -r)" ]]; then
		RESULT=$(grep "^$KERNEL_OPTION=" "/boot/config-$(uname -r)") || :;
	fi

	ANSWER=$(cut -d = -f 2 <<< "$RESULT");

	if [[ "x$ANSWER" = "xy" ]]; then
		FNRET=0;
	elif [[ "x$ANSWER" = "xn" ]]; then
		FNRET=1;
	else
		FNRET=2;
	fi

	if [ "$FNRET" -ne 0 -a -n "$MODULE_NAME" -a -d "/lib/modules/$(uname -r)" ]; then
		local MODULE_FILE=$(find "/lib/modules/$(uname -r)/" -type f -name "$MODULE_NAME.ko");

		if [[ -n "$MODULE_FILE" ]]; then
			if grep -qRE "^\s*blacklist\s+$MODULE_NAME\s*$" /etc/modprobe.d/ ; then
				FNRET=1;
			fi

			FNRET=0;
		fi
	fi
}

function is_a_partition {
	local PARTITION_NAME=$1;
	FNRET=128;

	if $(grep "[[:space:]]$PARTITION_NAME[[:space:]]" /etc/fstab | grep -vqE "^#"); then
		FNRET=0;
	else
		FNRET=1;
	fi
}

function add_option_to_fstab {
	local PARTITION=$1;
	local OPTION=$2;

	backup_file "/etc/fstab";
	sed -ie "s;\(.*\)\(\s*\)\s\($PARTITION\)\s\(\s*\)\(\w*\)\(\s*\)\(\w*\)*;\1\2 \3 \4\5\6\7,$OPTION;" /etc/fstab;
}

function remount_partition {
	local PARTITION=$1;

	mount -o remount "$PARTITION" >> $LOG_FILE 2>&1;
}

function apt_install {
	local PACKAGE=$1;

	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install "$PACKAGE" -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_purge {
	local PACKAGE=$1;

	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" purge "$PACKAGE" -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_update {
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" update -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_upgrade {
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_autoremove {
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" autoremove --purge -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_full_upgrade {
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" full-upgrade -y >> $DOWNLOADS_FILE;
	FNRET=0;
}

function apt_autoclean {
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" autoclean >> $DOWNLOADS_FILE;
	DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" clean >> $DOWNLOADS_FILE;
	FNRET=0;
}

function is_pkg_installed {
	PKG_NAME=$1;

	if $(dpkg -s "$PKG_NAME" 2> /dev/null | grep -q '^Status: install ') ; then
		FNRET=0;
	else
		FNRET=1;
	fi
}

yes_no "Are you sure you want to start?";

if [[ FNRET -eq 0 ]]; then
	logger "Aborting script execution...";
	exit;
fi

# Get the main user
get_response "What is the username of the main user?";

MAIN_USER=$FNRET;

d_IFS=$IFS;
IFS=$'\n';
USERS_INPUT_RAW=($(more $(find /home -name "README.desktop") | grep -oP "(?<=^Exec=x-www-browser \")([^\"]+)" | xargs wget -qO- | grep -Pzo "<b>Authorized Administrators(.|\n)*?(?=<\/pre)"));
is_admin=1;
IFS=' ';

USERS=();
ADMINS=();

for line in "${USERS_INPUT_RAW[@]}"; do
	if [[ "$line" =~ ^...Authorized\ Users ]]; then
		is_admin=0;
	elif [[ "$line" =~ ^[a-z]+ ]]; then
		username=$(echo $line | grep -Po "^[a-z]+");

		if [ $is_admin -eq 1 ]; then
			ADMINS+=("$username");
		else
			USERS+=("$username");
		fi
	fi
done

IFS=$d_IFS;


# Update apt cache
logger "Updating apt cache...";
apt_update;

# Update packages
logger "Updating apt packages...";
apt_upgrade;

logger "Fixing broken packages...";
dpkg --configure -a;
apt --fix-missing update;

# Disable the root user
logger "Disabling root user...";
passwd -l root >> $LOG_FILE 2>&1;

# Disable guest account
logger "Disabling guest account...";
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf;

# Enable UFW
logger "Enabling uncomplicated firewall...";

sed -i "/ipv6=/Id" /etc/default/ufw >> $LOG_FILE 2>&1;
echo "ipv6=no" >> /etc/default/ufw;

ufw enable >> $LOG_FILE 2>&1;
ufw deny 23 >> $LOG_FILE 2>&1;
ufw deny 2049 >> $LOG_FILE 2>&1;
ufw deny 515 >> $LOG_FILE 2>&1;
ufw deny 111 >> $LOG_FILE 2>&1;

#################################
#
# Manage groups, users, and passwords
#
#################################

d_IFS=$IFS;
IFS=' ';
logger "Admins: ${ADMINS[@]}";
logger "Users: ${USERS[@]}";
yes_no "Are these accounts correct?";
IFS=$d_IFS;

if [[ $FNRET -eq 1 ]]; then
	yes_no "Would you like to go through the process of account management?";

	if [[ $FNRET -eq 1 ]]; then
		ALL_USERS=($(getent passwd {1000..60000} | grep -o "^[^:]*" | tr "\n" " "));

		ALLOWED_USERS=("${USERS[@]} ${ADMINS[@]}");
		TOTAL=${#ALLOWED_USERS[@]};

		yes_no "Should unauthorized users be removed?";

		if [[ $FNRET -eq 1 ]]; then
			for USER in "${ALL_USERS[@]}"; do
				if [[ ! "${ADMINS[@]}" =~ "${USER}" && ! "${USERS[@]}" =~ "${USER}" && ! "${MAIN_USER}" == "${USER}" ]]; then
					yes_no "Remove user $USER?";

					if [[ $FNRET -eq 1 ]]; then
						userdel -r "${USER}" >> $LOG_FILE 2>&1;

						logger "Removed user $USER";
					fi
				fi
			done
		fi

		yes_no "Should passwords be changed?";

		if [[ $FNRET -eq 1 ]]; then
			# Change passwords

			REMOVE_SUDO_USER=($MAIN_USER);
			ALLOWED_USERS=("${ALLOWED_USERS[@]/$REMOVE_SUDO_USER}");

			random_password "16";
			PASSWORD=$FNRET;

			logger "Using password: $PASSWORD";

			echo $PASSWORD >> $PASSWORD_FILE;

			for i in "${!ALLOWED_USERS[@]}"; do
				USER=${ALLOWED_USERS[$i]};

				yes $PASSWORD | passwd "$USER" >> $LOG_FILE 2>&1;

				logger "Strengthening passwords... ("$(($i + 1))"/${TOTAL})" 1;
			done

			echo "";
		fi

		yes_no "Should sudoers be corrected?";

		if [[ $FNRET -eq 1 ]]; then
			# Set sudo users

			for i in "${!ADMINS[@]}"; do
				USER=${ADMINS[$i]};

				yes $PASSWORD | sudo passwd "$USER" >> $LOG_FILE 2>&1;
				usermod -aG sudo "$USER" > /dev/null 2>&1;

				logger "Adding admins to sudo... ("$(($i + 1))"/${#ADMINS[@]})" 1;
			done

			echo "";

			for i in "${!USERS[@]}"; do
				USER=${USERS[$i]}

				yes $PASSWORD | sudo passwd "$USER" >> $LOG_FILE 2>&1;
				deluser "$USER" sudo > /dev/null 2>&1;

				logger "Removing users from sudo... ("$(($i + 1))"/${#USERS[@]})" 1;
			done

			echo "";
		fi
	fi
fi

#################################
#
# Install packages
#
#################################

debconf-set-selections <<< "postfix postfix/mailname string ubuntu" >> $LOG_FILE 2>&1;
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'No configuration'" >> $LOG_FILE 2>&1;

INSTALL_PACKAGES=(
	"tripwire"
	"apparmor"
	"apparmor-profiles"
	"iptables"
	"iptables-persistent"
	"syslog-ng"
	"tripwire"
	"libpam-modules-bin"
	"ntp"
	"tcpd"
	"auditd"
	"libpam-cracklib"
	"libpam-modules"
	"logwatch"
	"postfix"
	"libdate-manip-perl"
	"rkhunter"
	"tiger"
	"clamav-daemon"
	"clamav"
	"p7zip-rar"
	"rarv"
	"unrar"
	"cron"
	"p7zip-full"
	"denyhosts"
	"route"
	"gdm3"
);

logger "Installing packages... (0/${#INSTALL_PACKAGES[@]})" 1;

for i in ${!INSTALL_PACKAGES[@]}; do
	PACKAGE=${INSTALL_PACKAGES[$i]};
	logger "Installing packages... ("$(($i + 1))"/${#INSTALL_PACKAGES[@]}) - $PACKAGE" 1;

	apt_install "$PACKAGE";
done

echo "";

#################################
#
# Verify disk partitions
#
#################################

PARTITIONS=(
	"/tmp"
	"/tmp"
	"/tmp"
	"/tmp"
	"/var"
	"/var/tmp"
	"/var/tmp"
	"/var/tmp"
	"/var/tmp"
	"/var/log"
	"/var/log/audit"
	"/home"
	"/home"
	"/media\S*"
	"/media\S*"
	"/media\S*"
	"/run/shm"
	"/run/shm"
	"/run/shm"
);

OPTIONS=(
	"-"
	"nodev"
	"nosuid"
	"noexec"
	"-"
	"-"
	"nodev"
	"nosuid"
	"noexec"
	"-"
	"-"
	"-"
	"nodev"
	"nodev"
	"noexec"
	"nosuid"
	"nodev"
	"nosuid"
	"noexec"
);

logger "Verifying partitions... (0/${#OPTIONS[@]})" 1;

for i in ${!PARTITIONS[@]}; do
	PARTITION=${PARTITIONS[$i]};
	OPTION=${OPTIONS[$i]};

	is_a_partition "$PARTITION";

	if [[ "$OPTION" != "-" ]]; then
		if [[ $FNRET -eq 1 ]]; then
			mount "$PARTITION" >> $LOG_FILE 2>&1;
		fi
	else
		if [[ $FNRET -eq 1 ]]; then
			add_option_to_fstab "$PARTITION" "$OPTION";
			remount_partition "$PARTITION";
		elif [[ $FNRET -eq 3 ]]; then
			remount_partition "$PARTITION";
		fi
	fi

	logger "Verifying partitions... ("$(($i + 1))"/${#OPTIONS[@]})" 1;
done

echo "";

#################################
#
# Fix incorrect file permissions
#
#################################

logger "Fixing world-writable directories...";

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null);

if [[ ! -z "$RESULT" ]]; then
	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t;
fi

logger "Fixing other file permissions...";

# update-rc.d autofs remove 2>/dev/null;
chown root:root /boot/grub/grub.cfg 2>/dev/null;
chmod 0400 /boot/grub/grub.cfg >> $LOG_FILE 2>&1;

for dir in $(cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	if echo "$EXCEPTIONS" | grep -q "$dir"; then
		RESULT=$(sed "s!$dir!!" <<< "$RESULT");
	fi

	if [[ -d $dir ]]; then
		dirperm=$(/bin/ls -ld "$dir" | cut -f1 -d" ");

		if [[ $(echo "$dirperm" | cut -c6 ) != "-" ]]; then
			chmod g-w "$dir" >> $LOG_FILE 2>&1;
		fi

		if [[ $(echo "$dirperm" | cut -c8 ) != "-" ]]; then
			chmod o-r "$dir" >> $LOG_FILE 2>&1;
		fi

		if [[ $(echo "$dirperm" | cut -c9 ) != "-" ]]; then
			chmod o-w "$dir" >> $LOG_FILE 2>&1;
		fi

		if [[ $(echo "$dirperm" | cut -c10 ) != "-" ]]; then
			chmod o-x "$dir" >> $LOG_FILE 2>&1;
		fi
	fi
done

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	for FILE in $DIR/.[A-Za-z0-9]*; do
		if [ ! -h "$FILE" -a -f "$FILE" ]; then
			FILEPERM=$(ls -ld "$FILE" | cut -f1 -d" ");

			if [[ $(echo "$FILEPERM" | cut -c6) != "-" ]]; then
				chmod g-w "$FILE" >> $LOG_FILE 2>&1;
			fi

			if [[ $(echo "$FILEPERM" | cut -c9) != "-" ]]; then
				chmod o-w "$FILE" >> $LOG_FILE 2>&1;
			fi
		fi
	done
done

PERMISSIONS="600";

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	for FILE in "$DIR/.netrc"; do
		if [ ! -h "$FILE" -a -f "$FILE" ]; then
			file_has_correct_permissions "$FILE" $PERMISSIONS;

			if [[ $FNRET -ne 0 ]]; then
				chmod 600 "$FILE" >> $LOG_FILE 2>&1;
			fi
		fi
	done
done

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read USER USERID DIR; do
	if [[ $USERID -ge 500 && -d "$DIR" && $USER != "nfsnobody" ]]; then
		OWNER=$(stat -L -c "%U" "$DIR");

		if [[ "$OWNER" != "$USER" ]]; then
			chown "$USER" "$DIR" >> $LOG_FILE 2>&1;
		fi
	fi
done

#################################
#
# Verify kernel settings
#
#################################

KERNEL_OPTIONS=(
	"CONFIG_CRAMFS"
	"CONFIG_VXFS_FS"
	"CONFIG_JFFS2_FS"
	"CONFIG_HFS_FS"
	"CONFIG_HFSPLUS_FS"
	"CONFIG_SQUASHFS"
	"CONFIG_UDF_FS"
);

MODULE_NAMES=(
	"cramfs"
	"freevxfs"
	"jffs2"
	"hfs"
	"hfsplus"
	"squashfs"
	"udf"
);

ERRORS=0;

logger "Verifying kernel options... (0/${#MODULE_NAMES[@]})" 1;

for i in ${!KERNEL_OPTIONS[@]}; do
	KERNEL_OPTION=${KERNEL_OPTIONS[$i]};
	MODULE_NAME=${MODULE_NAMES[$i]};

	is_kernel_option_enabled "$KERNEL_OPTION";

	if [[ $FNRET -eq 0 ]]; then
		ERRORS=$((ERRORS+1))
	fi

	logger "Verifying kernel options... ("$(($i + 1))"/${#MODULE_NAMES[@]})" 1;
done

logger "Verified ${#MODULE_NAMES[@]} kernel options and found $ERRORS errors";

#################################
#
# Apply sysctl settings
#
#################################

SYSCTL_PARAMS=(
	"net.ipv6.conf.all.accept_source_route"
	"net.ipv6.conf.default.accept_source_route"
	"kernel.core_uses_pid"
	"kernel.panic"
	"net.ipv4.tcp_synack_retries"
	"net.ipv4.conf.all.send_redirects"
	"net.ipv4.conf.default.send_redirects"
	"net.ipv4.conf.all.accept_source_route"
	"net.ipv4.conf.all.accept_redirects"
	"net.ipv4.conf.all.secure_redirects"
	"net.ipv4.conf.all.log_martians"
	"net.ipv4.conf.default.accept_source_route"
	"net.ipv4.conf.default.accept_redirects"
	"net.ipv4.conf.default.secure_redirects"
	"net.ipv4.icmp_echo_ignore_broadcasts"
	"net.ipv4.tcp_syncookies"
	"net.ipv4.conf.all.rp_filter"
	"net.ipv4.conf.default.rp_filter "
	"net.ipv6.conf.default.router_solicitations"
	"net.ipv6.conf.default.accept_ra_rtr_pref"
	"net.ipv6.conf.default.accept_ra_pinfo"
	"net.ipv6.conf.default.accept_ra_defrtr"
	"net.ipv6.conf.default.autoconf"
	"net.ipv6.conf.default.dad_transmits"
	"net.ipv6.conf.default.max_addresses"
	"fs.file-max"
	"kernel.pid_max"
	"net.ipv4.ip_local_port_range"
	"net.ipv4.tcp_rfc1337"
	"net.ipv6.conf.lo.disable_ipv6"
	"net.ipv6.conf.all.disable_ipv6"
	"net.ipv6.conf.default.disable_ipv6"
	"net.ipv4.ip_forward"
	"net.ipv4.conf.default.accept_source_route"
	"kernel.sysrq"
	"fs.protected_hardlinks"
	"fs.protected_symlinks"
	"net.ipv4.icmp_ignore_bogus_error_responses"
	"kernel.exec-shield"
	"kernel.randomize_va_space"
	"net.ipv4.icmp_echo_ignore_all"
	"net.ipv4.conf.default.log_martians"
	"net.core.rmem_max"
	"net.core.wmem_max"
	"net.ipv4.tcp_rmem"
	"net.ipv4.tcp_wmem"
	"net.core.netdev_max_backlog"
	"net.ipv4.tcp_window_scaling"
	"net.ipv6.conf.all.accept_ra"
	"net.ipv6.conf.default.accept_ra"
	"fs.suid_dumpable"
	"net.ipv4.tcp_max_syn_backlog"
	"net.ipv4.tcp_syn_retries"
	"net.ipv6.conf.all.accept_redirects"
	"net.ipv6.conf.default.accept_redirects"
	"kernel.kptr_restrict"
	"vm.panic_on_oom"
);

SYSCTL_EXP_RESULTS=(
	"0" "0" "1" "10" "5" "0" "0" "0" "0" "0" "1" "0"
	"0" "0" "1" "1" "1" "1" "0" "0" "0" "0" "0" "0"
	"1" "65535" "65536" "2000 65000" "1" "1" "1" "1"
	"0" "0" "0" "1" "1" "1" "1" "2" "1" "1" "8388608"
	"8388608" "10240 87380 12582912" "10240 87380 12582912"
	"5000" "1" "0" "0" "0" "2048" "5" "0" "0" "2" "1"
);

logger "Applying sysctl settings... (0/${#SYSCTL_EXP_RESULTS[@]})" 1;

for i in ${!SYSCTL_PARAMS[@]}; do
	SYSCTL_PARAM=${SYSCTL_PARAMS[$i]};
	SYSCTL_EXP_RESULT=${SYSCTL_EXP_RESULTS[$i]};

	has_sysctl_param_expected_result "$SYSCTL_PARAM" "$SYSCTL_EXP_RESULT";
	if [[ $FNRET -ne 0 ]]; then
		sysctl_set_param "$SYSCTL_PARAM" "$SYSCTL_EXP_RESULT";
	fi 

	logger "Applying sysctl settings... ("$(($i + 1))"/${#SYSCTL_EXP_RESULTS[@]}) - $SYSCTL_PARAM" 1;
done

logger "Applied ${#SYSCTL_EXP_RESULTS[@]} sysctl settings";

#################################
#
# Purge packages
#
#################################

PURGE_PACKAGES=(
	"prelink"
	"nis"
	"rsh-client"
	"rsh-redone-client"
	"heimdal-clients"
	"talk"
	"inetutils-talk"
	"openbsd-inetd"
	"xinetd"
	"rlinetd"
	"udhcpd"
	"isc-dhcp-server"
	#	"libcups2"
	#	"libcupscgi1"
	#	"libcupsimage2"
	#	"libcupsmime1"
	#	"libcupsppdc1"
	#	"cups-common"
	#	"cups-client"
	#	"cups-ppdc"
	#	"libcupsfilters1"
	#	"cups-filters"
	#	"cups"
	#	"avahi-daemon"
	#	"libavahi-common-data"
	#	"libavahi-common3"
	#	"libavahi-core7"
	# "xserver-xorg-core"
	# "xserver-xorg-core-dbg"
	# "xserver-common"
	# "xserver-xephyr"
	# "xserver-xfbdev"
	"tightvncserver"
	"vnc4server"
	# "fglrx-driver"
	# "xvfb"
	# "xserver-xorg-video-nvidia-legacy-173xx"
	# "xserver-xorg-video-nvidia-legacy-96xx"
	# "xnest"
	"snmpd"
	"slapd"
	"squid3"
	"squid"
	"citadel-server"
	"courier-imap"
	"cyrus-imapd-2.4"
	"dovecot-imapd"
	"mailutils-imap4d"
	"courier-pop"
	"cyrus-pop3d-2.4"
	"dovecot-pop3d"
	"heimdal-servers"
	"mailutils-pop3d"
	"popa3d"
	"solid-pop3d"
	"xmail"
	"lighttpd"
	"micro-httpd"
	"mini-httpd"
	"yaws"
	"boa"
	"bozohttpd"
	"ftpd"
	"ftpd-ssl"
	"heimdal-servers"
	"inetutils-ftpd"
	"krb5-ftpd"
	"muddleftpd"
	"proftpd-basic"
	"pure-ftpd"
	"pure-ftpd-ldap"
	"pure-ftpd-mysql"
	"pure-ftpd-postgresql"
	"twoftpd-run"
	"wzdftpd"
	"bind9"
	"unbound"
	"rpcbind"
	"nfs-kernel-server"
	"netcat"
	"nc"
	"netcat-*"
	"ophcrack"
);

logger "Purging packages... (0/${#PURGE_PACKAGES[@]})" 1;

for i in ${!PURGE_PACKAGES[@]}; do
	PACKAGE=${PURGE_PACKAGES[$i]};
	logger "Purging packages... ("$(($i + 1))"/${#PURGE_PACKAGES[@]}) - $PACKAGE" 1;

	is_pkg_installed "$PACKAGE";

	if [[ $FNRET -eq 0 ]]; then
		apt_purge "$PACKAGE";
	fi
done

logger "Purged ${#PURGE_PACKAGES[@]} packages";

#################################
#
# Remove all games
#
#################################

logger "Searching for games..." 1;

ALL_GAMES=($(apt-cache search "game" | grep -o "^[^ ]*"));
ALL_PACKAGES=($(dpkg -l | sed -E 's/ii\s+([^ ]*).*/\1/p'));

GAMES=();

for GAME in "${ALL_GAMES[@]}"; do
	if [[ "${ALL_PACKAGES[@]}" =~ "${GAME}" ]]; then
		GAMES+=($GAME)
	fi
done

logger "Purging games... (0/${#GAMES[@]})" 1;

for i in "${!GAMES[@]}"; do
	GAME=${GAMES[$i]};

	logger "Purging games... ("$(($i + 1))"/${#GAMES[@]}) - $GAME" 1;

	apt_purge "$GAME";
done

logger "Purged ${#GAMES[@]} games";

#################################
#
# Purge more packages
#
#################################

MASTER_PACKAGES=(
	"rsh-server,rsh-redone-server,heimdal-servers"
	"inetutils-talkd,talkd"
	"telnetd,inetutils-telnetd,telnetd-ssl,krb5-telnetd,heimdal-servers"
	"tftpd,tftpd-hpa,atftpd"
);

MASTER_FILES=(
	"/etc/inetd.conf"
	"/etc/inetd.conf"
	"/etc/inetd.conf"
	"/etc/inetd.conf"
);

MASTER_PATTERNS=(
	"^(shell|login|exec)"
	"^(talk|ntalk)"
	"^telnet"
	"^tftp"
);

logger "Purging more package files... (0/${#MASTER_PATTERNS[@]})";

d_IFS=$IFS;

for i in ${!MASTER_PACKAGES[@]}; do
	IFS=',';
	PACKAGES=(${MASTER_PACKAGES[$i]});
	IFS=' ';
	FILE=${MASTER_FILES[$i]};
	PATTERN=${MASTER_PATTERNS[$i]};

	logger "Purging more package files... ("$(($i + 1))"/${#MASTER_PATTERNS[@]})";

	for PACKAGE in $PACKAGES; do
		is_pkg_installed "$PACKAGE";

		if [[ $FNRET -eq 0 ]]; then
			apt-get purge "$PACKAGE" -y >> $DOWNLOADS_FILE;
		fi

		check_file_existance "$FILE";

		if [[ $FNRET -eq 0 ]]; then
			file_does_pattern_exist "$FILE" "$PATTERN";

			if [[ $FNRET -eq 0 ]]; then
				backup_file "$FILE";
				ESCAPED_PATTERN=$(sed "s/|\|(\|)/\\\&/g" <<< "$PATTERN");
				sed -ie "s/$ESCAPED_PATTERN/#&/g" "$FILE";
			fi
		fi
	done
done

IFS=$d_IFS;

logger "Purged ${#MASTER_PATTERNS[@]} package files";

#################################
#
# Purge inetd configurations
#
#################################

MASTER_PATTERNS=(
	"^chargen"
	"^daytime"
	"^echo"
	"^discard"
	"^time"
);

logger "Purging inetd.conf configurations... (0/${#MASTER_PATTERNS[@]})" 1;

for i in ${!MASTER_PATTERNS[@]}; do
	FILE="/etc/inetd.conf";
	PATTERN=${MASTER_PATTERNS[$i]};

	logger "Purging inetd.conf configurations... ("$(($i + 1))"/${#MASTER_PATTERNS[@]})" 1;

	check_file_existance $FILE;

	if [[ $FNRET -eq 0 ]]; then
		file_does_pattern_exist $FILE "$PATTERN";

		if [[ $FNRET -eq 0 ]]; then
			backup_file $FILE;
			ESCAPED_PATTERN=$(sed "s/|\|(\|)/\\\&/g" <<< "$PATTERN");
			sed -ie "s/$ESCAPED_PATTERN/#&/g" $FILE;
		fi
	fi
done

logger "Purged ${#MASTER_PATTERNS[@]} inetd.conf configurations";

#################################
#
# Apply auditd settings
#
#################################

AUDIT_PARAMS=(
	"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
	"-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
	"-a always,exit -F arch=b64 -S clock_settime -k time-change"
	"-a always,exit -F arch=b32 -S clock_settime -k time-change"
	"-w /etc/localtime -p wa -k time-change"
	"-w /etc/group -p wa -k identity"
	"-w /etc/passwd -p wa -k identity"
	"-w /etc/gshadow -p wa -k identity"
	"-w /etc/shadow -p wa -k identity"
	"-w /etc/security/opasswd -p wa -k identity"
	"-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale"
	"-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale"
	"-w /etc/issue -p wa -k system-locale"
	"-w /etc/issue.net -p wa -k system-locale"
	"-w /etc/hosts -p wa -k system-locale"
	"-w /etc/network -p wa -k system-locale"
	"-w /etc/selinux/ -p wa -k MAC-policy"
	"-w /var/log/faillog -p wa -k logins"
	"-w /var/log/lastlog -p wa -k logins"
	"-w /var/log/tallylog -p wa -k logins"
	"-w /var/run/utmp -p wa -k session"
	"-w /var/log/wtmp -p wa -k session"
	"-w /var/log/btmp -p wa -k session"
	"-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	"-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
	"-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
	"-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
	"-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
	"-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
	"-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
	"-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
	"-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
	"-w /etc/sudoers -p wa -k sudoers"
	"-w /etc/sudoers.d/ -p wa -k sudoers"
	"-w /var/log/auth.log -p wa -k sudoaction"
	"-w /sbin/insmod -p x -k modules"
	"-w /sbin/rmmod -p x -k modules"
	"-w /sbin/modprobe -p x -k modules"
	"-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
	"-e 2"
);

FILE='/etc/audit/audit.rules';

logger "Applying auditd settings... (0/${#AUDIT_PARAMS[@]})" 1;

d_IFS=$IFS;

for i in ${!AUDIT_PARAMS[@]}; do
	AUDIT_VALUE=${AUDIT_PARAMS[$i]};

	file_does_pattern_exist $FILE "$AUDIT_VALUE";

	if [[ $FNRET -ne 0 ]]; then
		append_to_file $FILE "$AUDIT_VALUE";
		eval $(pkill -HUP -P 1 auditd);
	fi

	logger "Applying auditd settings... ("$(($i + 1))"/${#AUDIT_PARAMS[@]}) - $AUDIT_VALUE" 1;
done

IFS=$'\n';

SUDO_CMD='sudo -n';
AUDIT_PARAMS1=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" }');
FILE='/etc/audit/audit.rules';

for AUDIT_VALUE in $AUDIT_PARAMS1; do
	file_does_pattern_exist $FILE "$AUDIT_VALUE";

	if [[ $FNRET -ne 0 ]]; then
		append_to_file $FILE "$AUDIT_VALUE";
		eval $(pkill -HUP -P 1 auditd);
	fi
done

logger "Applied ${#AUDIT_PARAMS[@]} auditd settings";

IFS=$d_IFS;

#################################
#
# Firefox settings
#
#################################

logger "Closing Firefox..."
pkill firefox >> $LOG_FILE 2>&1

logger "Updating Firefox settings... (looking for profile)" 1;
profile=$(ls /home/${MAIN_USER}/.mozilla/firefox | grep .default$)
logger "Updating Firefox settings... (found profile ${profile})";

FIREFOX_SETTINGS=(
	"browser.safebrowsing.downloads.remote.block_uncommon"
	"browser.safebrowsing.malware.enabled"
	"browser.safebrowsing.phishing.enabled"
	"disable_open_during_load"
	"browser.safebrowsing.downloads.enabled"
	"browser.safebrowsing.downloads.remote.block_potentially_unwanted"
	"urlclassifier.malwareTable"
	"media.autoplay.default"
	"permissions.default.camera"
	"permissions.default.desktop-notification"
	"permissions.default.geo"
	"permissions.default.microphone"
	"network.cookie.lifetimePolicy"
	"signon.rememberSignons"
	"xpinstall.whitelist.required"
	"datareporting.healthreport.uploadEnabled"
	"browser.crashReports.unsubmittedCheck.autoSubmit2"
	"privacy.donottrackheader.enabled"
	"accessibility.force_disabled"
);

logger "Purging Firefox settings... (0/${#FIREFOX_SETTINGS[@]})" 1;

for i in ${!FIREFOX_SETTINGS[@]}; do
	SETTING=${FIREFOX_SETTINGS[$i]};

	logger "Purging Firefox settings... ("$(($i + 1))"/${#FIREFOX_SETTINGS[@]})" 1;

	sed -i "/$SETTING/d" /home/${MAIN_USER}/.mozilla/firefox/"$profile"/prefs.js >> $LOG_FILE 2>&1;
done

logger "Purged ${#FIREFOX_SETTINGS[@]} Firefox settings";

FIREFOX_USER_PREFERENCES=(
	'"media.autoplay.default", 1'
	'"urlclassifier.malwareTable", "goog-malware-proto,test-harmful-simple,test-malware-simple"'
	'"permissions.default.camera", 2'
	'"permissions.default.desktop-notification", 2'
	'"permissions.default.geo", 2'
	'"permissions.default.microphone", 2'
	'"network.cookie.lifetimePolicy", 2'
	'"signon.rememberSignons", false'
	'"xpinstall.whitelist.required", true'
	'"datareporting.healthreport.uploadEnabled", false'
	'"browser.crashReports.unsubmittedCheck.autoSubmit2", false'
	'"accessibility.force_disabled", 1'
	'"privacy.donottrackheader.enabled", true'
);

logger "Updating Firefox settings... (0/${#FIREFOX_USER_PREFERENCES[@]})" 1;

for i in ${!FIREFOX_USER_PREFERENCES[@]}; do
	SETTING=${FIREFOX_USER_PREFERENCES[$i]};

	logger "Updating Firefox settings... ("$(($i + 1))"/${#FIREFOX_USER_PREFERENCES[@]})" 1;

	echo "user_pref($SETTING);" >> /home/${MAIN_USER}/.mozilla/firefox/"$profile"/prefs.js;
done

logger "Updated ${#FIREFOX_USER_PREFERENCES[@]} Firefox settings";

#################################
#
# Set grub password
#
#################################

# logger "Setting grub password...";

# GRUB_PASSWORD=$(yes "$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 | cut -c33- | tr -d $'\n');

# printf "#!/bin/sh\nexec tail -n +3 \$0\n\nset superusers=\"root\"\npassword_pbkdf2 root $GRUB_PASSWORD" > /etc/grub.d/40_custom;

#################################
#
# Configure miscellaneous files
#
#################################

logger "Configuring miscellaneous files...";

logger "Editing DenyHosts settings...";

sed -i '/ADMIN_EMAIL/d' /etc/denyhosts.conf >> $LOG_FILE 2>&1;
sed -i '/SMTP_FROM/d' /etc/denyhosts.conf >> $LOG_FILE 2>&1;
echo "ADMIN_EMAIL = pretendthisemailexists@gmail.com" >> /etc/denyhosts.conf;
echo "SMTP_FROM = denyhostnotifications@gmail.com" >> /etc/denyhosts.conf ;

/etc/init.d/denyhosts restart >> $LOG_FILE 2>&1;

logger "Enabling daily automatic updates...";

echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades;
echo 'APT::Periodic::Download-Upgradeable-Packages "1";' >> /etc/apt/apt.conf.d/20auto-upgrades;
echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/20auto-upgrades;
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades;

unattended-upgrades --dry-run --debug >> $LOG_FILE 2>&1;

LIMIT_FILE='/etc/security/limits.conf';
LIMIT_PATTERN='^\*[[:space:]]*hard[[:space:]]*core[[:space:]]*0$';

file_does_pattern_exist $LIMIT_FILE "$LIMIT_PATTERN";

if [[ $FNRET -ne 0 ]]; then
	append_to_file $LIMIT_FILE "* hard core 0"
fi

PACKAGE='ntp';
NTP_CONF_DEFAULT_PATTERN='^restrict -4 default (kod nomodify notrap nopeer noquery|ignore)';
NTP_CONF_FILE='/etc/ntp.conf';
NTP_INIT_PATTERN='RUNASUSER=ntp';
NTP_INIT_FILE='/etc/init.d/ntp';

file_does_pattern_exist $NTP_CONF_FILE "$NTP_CONF_DEFAULT_PATTERN";

if [[ $FNRET -ne 0 ]]; then
	append_to_file $NTP_CONF_FILE "restrict -4 default kod notrap nomodify nopeer noquery";
fi

file_does_pattern_exist $NTP_INIT_FILE "^$NTP_INIT_PATTERN";

if [[ $FNRET -ne 0 ]]; then
	file_addline_before_pattern $NTP_INIT_FILE $NTP_INIT_PATTERN "^UGID";
fi

PACKAGE='rsync';
RSYNC_DEFAULT_PATTERN='RSYNC_ENABLE=false';
RSYNC_DEFAULT_FILE='/etc/default/rsync';
RSYNC_DEFAULT_PATTERN_TO_SEARCH='RSYNC_ENABLE=true';

is_pkg_installed $PACKAGE;

if [[ $FNRET -eq 0 ]]; then
	file_does_pattern_exist $RSYNC_DEFAULT_FILE "^$RSYNC_DEFAULT_PATTERN";

	if [[ $FNRET -ne 0 ]]; then
		replace_in_file $RSYNC_DEFAULT_FILE $RSYNC_DEFAULT_PATTERN_TO_SEARCH $RSYNC_DEFAULT_PATTERN;
	fi
fi

PACKAGE='tcpd'
FILE='/etc/hosts.allow'

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

FILE='/etc/hosts.allow';
PERMISSIONS='644';

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/hosts.deny'
PATTERN='ALL: ALL'

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_does_pattern_exist $FILE "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	append_to_file $FILE "$PATTERN";
fi

FILE='/etc/hosts.deny';
PERMISSIONS='644';

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/audit/auditd.conf';
PATTERN='max_log_file';
VALUE=5;

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_does_pattern_exist $FILE "^$PATTERN[[:space:]]";

if [[ $FNRET -ne 0 ]]; then
	append_to_file $FILE "$PATTERN = $VALUE";
fi

FILE='/etc/audit/auditd.conf';
OPTIONS='space_left_action=email action_mail_acct=root admin_space_left_action=halt';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

for AUDIT_OPTION in $OPTIONS; do
	AUDIT_PARAM=$(echo "$AUDIT_OPTION" | cut -d= -f 1);
	AUDIT_VALUE=$(echo "$AUDIT_OPTION" | cut -d= -f 2);
	PATTERN="^$AUDIT_PARAM[[:space:]]*=[[:space:]]*$AUDIT_VALUE";

	file_does_pattern_exist $FILE "$PATTERN";

	if [[ $FNRET -ne 0 ]]; then
		file_does_pattern_exist $FILE "^$AUDIT_PARAM";

		if [[ $FNRET -ne 0 ]]; then
			append_to_file $FILE "$AUDIT_PARAM = $AUDIT_VALUE";
		else
			replace_in_file $FILE "^$AUDIT_PARAM[[:space:]]*=.*" "$AUDIT_PARAM = $AUDIT_VALUE";
		fi
	fi
done

FILE='/etc/audit/auditd.conf';
OPTIONS='max_log_file_action=keep_logs';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

for AUDIT_OPTION in $OPTIONS; do
	AUDIT_PARAM=$(echo $AUDIT_OPTION | cut -d= -f 1);
	AUDIT_VALUE=$(echo $AUDIT_OPTION | cut -d= -f 2);
	PATTERN="^$AUDIT_PARAM[[:space:]]*=[[:space:]]*$AUDIT_VALUE";

	file_does_pattern_exist $FILE "$PATTERN";

	if [[ $FNRET -ne 0 ]]; then
		file_does_pattern_exist $FILE "^$AUDIT_PARAM";

		if [[ $FNRET -ne 0 ]]; then
			append_to_file $FILE "$AUDIT_PARAM = $AUDIT_VALUE";
		else
			replace_in_file $FILE "^$AUDIT_PARAM[[:space:]]*=.*" "$AUDIT_PARAM = $AUDIT_VALUE";
		fi
	fi
done

PACKAGE='auditd';
SERVICE_NAME='auditd';

is_service_enabled $SERVICE_NAME;

if [[ $FNRET -ne 0 ]]; then
	update-rc.d $SERVICE_NAME remove >	/dev/null 2>&1;
	update-rc.d $SERVICE_NAME defaults > /dev/null 2>&1;
fi

FILE='/etc/default/grub';
OPTIONS='GRUB_CMDLINE_LINUX="audit=1"';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

for GRUB_OPTION in $OPTIONS; do
	GRUB_PARAM=$(echo $GRUB_OPTION | cut -d= -f 1);
	GRUB_VALUE=$(echo $GRUB_OPTION | cut -d= -f 2,3);
	PATTERN="^$GRUB_PARAM=$GRUB_VALUE";

	file_does_pattern_exist $FILE "$PATTERN";

	if [[ $FNRET -ne 0 ]]; then
		file_does_pattern_exist $FILE "^$GRUB_PARAM";

		if [[ $FNRET -ne 0 ]]; then
			append_to_file $FILE "$GRUB_PARAM = $GRUB_VALUE";
		else
			replace_in_file $FILE "^$GRUB_PARAM=.*" "$GRUB_PARAM=$GRUB_VALUE";
		fi
	fi
done

SERVICE_NAME="syslog-ng";

is_service_enabled $SERVICE_NAME;

if [[ $FNRET -ne 0 ]]; then
	update-rc.d $SERVICE_NAME remove > /dev/null 2>&1;
	update-rc.d $SERVICE_NAME defaults > /dev/null 2>&1;
fi

PERMISSIONS='640';
USER='root';
GROUP='adm';

FILES=$(grep "file(" $SYSLOG_BASEDIR/syslog-ng.conf | grep '"' | cut -d'"' -f 2);

for FILE in $FILES; do
	check_file_existance "$FILE";

	if [[ $FNRET -ne 0 ]]; then
		touch "$FILE";
	fi

	file_has_correct_ownership "$FILE" $USER $GROUP;

	if [[ $FNRET -ne 0 ]]; then
		chown $USER:$GROUP "$FILE" >> $LOG_FILE 2>&1;
	fi

	file_has_correct_permissions "$FILE" $PERMISSIONS;

	if [[ $FNRET -ne 0 ]]; then
		chmod 0$PERMISSIONS "$FILE" >> $LOG_FILE 2>&1;
	fi
done

FILES='/etc/crontab /etc/cron.d/*';
PATTERN='tripwire --check';

file_does_pattern_exist "$FILES" "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	echo "0 10 * * * root /usr/sbin/tripwire --check > /dev/shm/tripwire_check 2>&1 " > /etc/cron.d/CIS_8.3.2_tripwire;
fi

FILE='/etc/crontab';
PERMISSIONS='600';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/cron.hourly';
PERMISSIONS='700';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/cron.daily';
PERMISSIONS='700';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/cron.weekly';
PERMISSIONS='700';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/cron.monthly';
PERMISSIONS='700';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/cron.d';
PERMISSIONS='700';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILES_ABSENT='/etc/cron.deny /etc/at.deny';
FILES_PRESENT='/etc/cron.allow /etc/at.allow';
PERMISSIONS='400';
USER='root';
GROUP='root';

for FILE in $FILES_PRESENT; do
	check_file_existance "$FILE";
	
	if [[ $FNRET -ne 0 ]]; then
		touch "$FILE";
	fi

	file_has_correct_ownership "$FILE" $USER $GROUP;

	if [[ $FNRET -ne 0 ]]; then
		chown $USER:$GROUP "$FILE" >> $LOG_FILE 2>&1;
	fi

	file_has_correct_permissions "$FILE" $PERMISSIONS;

	if [[ $FNRET -ne 0 ]]; then
		chmod 0$PERMISSIONS "$FILE" >> $LOG_FILE 2>&1;
	fi
done

PACKAGE='libpam-cracklib';
PATTERN='^password.*pam_cracklib.so';
FILE='/etc/pam.d/common-password';

file_does_pattern_exist $FILE "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	file_addline_before_pattern $FILE "password	requisite			 pam_cracklib.so retry=3 minlen=8 difok=3 dictcheck=1 maxsequence=5 maxrepeat=3 minclass=2" "# pam-auth-update(8) for details.";
fi 

PACKAGE='libpam-modules-bin';
PATTERN='^auth[[:space:]]*required[[:space:]]*pam_tally[2]?.so';
FILE='/etc/pam.d/login';

file_does_pattern_exist $FILE "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	file_addline_before_pattern $FILE "auth	required	pam_tally.so onerr=fail deny=6 unlock_time=1800" "# Uncomment and edit \/etc\/security\/time.conf if you need to set";
fi 

PACKAGE='libpam-modules';
PATTERN='^password.*remember';
FILE='/etc/pam.d/common-password';

file_does_pattern_exist $FILE "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	file_addline_before_pattern $FILE "password [success=1 default=ignore] pam_unix.so obscure sha512 remember=5" "# pam-auth-update(8) for details.";
fi 

PACKAGE='openssh-server';
OPTIONS='Protocol=2';
FILE='/etc/ssh/sshd_config';

for SSH_OPTION in $OPTIONS; do
		SSH_PARAM=$(echo $SSH_OPTION | cut -d= -f 1);
		SSH_VALUE=$(echo $SSH_OPTION | cut -d= -f 2);
		PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE";

		file_does_pattern_exist $FILE "$PATTERN";

		if [[ $FNRET -ne 0 ]]; then
			file_does_pattern_exist $FILE "^$SSH_PARAM";

			if [[ $FNRET -ne 0 ]]; then
				append_to_file $FILE "$SSH_PARAM $SSH_VALUE";
			else
				replace_in_file $FILE "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE";
			fi

			/etc/init.d/ssh reload > /dev/null 2>&1;
		fi
done

PACKAGE='openssh-server';
OPTIONS='LogLevel=INFO';
FILE='/etc/ssh/sshd_config';

for SSH_OPTION in $OPTIONS; do
		SSH_PARAM=$(echo $SSH_OPTION | cut -d= -f 1);
		SSH_VALUE=$(echo $SSH_OPTION | cut -d= -f 2);
		PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE";

		file_does_pattern_exist $FILE "$PATTERN";

		if [[ $FNRET -ne 0 ]]; then
			file_does_pattern_exist $FILE "^$SSH_PARAM";

			if [[ $FNRET -ne 0 ]]; then
				append_to_file $FILE "$SSH_PARAM $SSH_VALUE";
			else
				replace_in_file $FILE "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE";
			fi

			/etc/init.d/ssh reload > /dev/null 2>&1;
		fi
done

FILE='/etc/ssh';
PERMISSIONS='444';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod -R 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/ssh/sshd_config';
PERMISSIONS='600';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/var/log';
PERMISSIONS='444';
USER='root';
GROUP='root';

check_file_existance $FILE;

if [[ $FNRET -ne 0 ]]; then
	touch $FILE;
fi

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod -R 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

PACKAGE='login';
PATTERN='^auth[[:space:]]*required[[:space:]]*pam_wheel.so';
FILE='/etc/pam.d/su';

file_does_pattern_exist $FILE "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	file_addline_before_pattern $FILE "auth		 required	 pam_wheel.so" "# Uncomment this if you want wheel members to be able to";
fi 

SHELL='/bin/false';
FILE='/etc/passwd';
RESULT='';

RESULT=$(egrep -v "^\+" $FILE | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}');

d_IFS=$IFS;
IFS=$'\n';

for LINE in $RESULT; do
	ACCOUNT=$( echo "$LINE" | cut -d: -f 1 );

	if echo "$EXCEPTIONS" | grep -q "$ACCOUNT"; then
		RESULT=$(sed "s!$LINE!!" <<< "$RESULT");
	fi
done

if [[ ! -z "$RESULT" ]]; then
	for USER in $( echo "$RESULT" | cut -d: -f 1 ); do
		usermod -s $SHELL "$USER";
	done
fi

IFS=$d_IFS;

USER='root';
EXPECTED_GID='0';

if [[ $(grep "^root:" /etc/passwd | cut -f4 -d:) -ne 0 ]]; then
	usermod -g $EXPECTED_GID $USER;
fi

USER='root';
PATTERN='umask 077';
FILES_TO_SEARCH='/etc/bash.bashrc /etc/profile.d /etc/profile';
FILE='/etc/profile.d/CIS_10.4_umask.sh';

SEARCH_RES=0;

for FILE_SEARCHED in $FILES_TO_SEARCH; do
	if [[ $SEARCH_RES -eq 1 ]]; then break; fi

	if test -d "$FILE_SEARCHED"; then
		for file_in_dir in $(ls "$FILE_SEARCHED"); do
			file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN";

			if [[ $FNRET -eq 0 ]]; then
				SEARCH_RES=1;
				break;
			fi
		done
	else
		file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN";

		if [[ $FNRET -eq 0 ]]; then
			SEARCH_RES=1;
		fi
	fi
done

if [[ $SEARCH_RES -eq 0 ]]; then
	touch $FILE;
	chmod 644 $FILE >> $LOG_FILE 2>&1;
	append_to_file $FILE "$PATTERN";
fi

PERMISSIONS='644';
USER='root';
GROUP='root';
FILES=("/etc/motd" "/etc/issue" "/etc/issue.net");

for FILE in $FILES; do
	check_file_existance "$FILE";

	if [[ $FNRET -ne 0 ]]; then
		touch "$FILE" 
	fi;

	file_has_correct_ownership "$FILE" $USER $GROUP;

	if [[ $FNRET -ne 0 ]]; then
		chown $USER:$GROUP "$FILE" >> $LOG_FILE 2>&1;
	fi

	file_has_correct_permissions "$FILE" $PERMISSIONS;

	if [[ $FNRET -ne 0 ]]; then
		chmod 0$PERMISSIONS "$FILE" >> $LOG_FILE 2>&1;
	fi
done

FILES='/etc/motd /etc/issue /etc/issue.net';
PATTERN='(\\v|\\r|\\m|\\s)';

for FILE in $FILES; do
	file_does_pattern_exist "$FILE" "$PATTERN";

	if [[ $FNRET -eq 0 ]]; then
		delete_line_in_file "$FILE" $PATTERN;
	fi
done

FILE='/etc/passwd';
PERMISSIONS='644';

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/shadow';
PERMISSIONS='640';

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/group';
PERMISSIONS='644';

file_has_correct_permissions $FILE $PERMISSIONS;

if [[ $FNRET -ne 0 ]]; then
	chmod 0$PERMISSIONS $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/passwd';
USER='root';
GROUP='root';

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/shadow';
USER='root';
GROUP='shadow';

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

FILE='/etc/group';
USER='root';
GROUP='root';

file_has_correct_ownership $FILE $USER $GROUP;

if [[ $FNRET -ne 0 ]]; then
	chown $USER:$GROUP $FILE >> $LOG_FILE 2>&1;
fi

#################################
#
# Verifying settings
#
#################################

PATTERN='NX[[:space:]]\(Execute[[:space:]]Disable\)[[:space:]]protection:[[:space:]]active';

if grep -q ' nx ' /proc/cpuinfo; then
	if grep -qi 'noexec=off' /proc/cmdline; then
		FNRET=1;
	else
		FNRET=0;
	fi
else
	FNRET=1;
fi

dmesg_does_pattern_exist "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	is_nx_supported_and_enabled;

	if [[ $FNRET -ne 0 ]]; then
		logger "$PATTERN is not present in dmesg and NX seems unsupported or disabled\n";
		logger "\e[91mnoexec is unsupported or disabled\e[39m";
	else
		logger "\e[32mnoexec is supported and enabled\e[39m";
	fi
fi

RESULT=$(netstat -an | grep LIST | grep ":25[[:space:]]") || :;
RESULT=${RESULT:-};

if [[ -z "$RESULT" ]]; then
	logger "\e[32mNothing is listening on port 25\e[39m";
else
	if	$(grep -q "127.0.0.1" <<< "$RESULT"); then
		logger "\e[32mMessage transfer agent is localhost only\e[39m";
	else
		logger "\e[91mMessage transfer agent listens worldwide, consider changing this\e[39m";
	fi
fi

PATTERN='^destination.*(tcp|udp)[[:space:]]*\([[:space:]]*\".*\"[[:space:]]*\)';

FILES="$SYSLOG_BASEDIR/syslog-ng.conf $SYSLOG_BASEDIR/conf.d/*";

file_does_pattern_exist "$FILES" "$PATTERN";

if [[ $FNRET -ne 0 ]]; then
	logger "\e[91mPlease set a remote host to send your logs ($FILES)\e[39m";
else
	logger "\e[32mLogs are being sent to a remote host\e[39m";
fi

KERNEL_OPTION="CONFIG_AUDIT";

is_kernel_option_enabled "^$KERNEL_OPTION=";

if [[ $FNRET -eq 0 ]]; then
	logger "$KERNEL_OPTION is enabled\n";
	logger "\e[32mKernel option $KERNEL_OPTION is enabled\e[39m";
else
	logger "\e[91mKernel option $KERNEL_OPTION is disabled: recompile kernel\e[39m";
fi

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null);

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mWorld-writable files present, fixing...\e[39m";

	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null|	xargs chmod o-w;
fi

USER='root';

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls 2>/dev/null);

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mUnowned files present, fixing...\e[39m";

	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -print 2>/dev/null | xargs chown $USER;
fi

GROUP='root';

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls 2>/dev/null);

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mUngrouped files present, fixing...\e[39m";

	df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -print 2>/dev/null | xargs chgrp $GROUP;
fi

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print 2>/dev/null);

for BINARY in $RESULT; do
	if grep -q "$BINARY" <<< "$EXCEPTIONS"; then
		RESULT=$(sed "s!$BINARY!!" <<< "$RESULT");
	fi
done

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mSUID files present (suid.txt)\e[39m";

	FORMATTED_RESULT=$(sed "s/ /\n/g" <<< "$RESULT" | sort | uniq | tr '\n' ' ');

	echo "$FORMATTED_RESULT" > suid.txt;
else
	logger "\e[32mNo unknown SUID files present\e[39m";
fi

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print 2>/dev/null);

for BINARY in $RESULT; do
	if grep -q "$BINARY" <<< "$EXCEPTIONS"; then
		RESULT=$(sed "s!$BINARY!!" <<< "$RESULT");
	fi
done
if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mSGID files present (sgid.txt)\e[39m";

	FORMATTED_RESULT=$(sed "s/ /\n/g" <<< "$RESULT" | sort | uniq | tr '\n' ' ');

	echo "$FORMATTED_RESULT" > sgid.txt;
else
	logger "\e[32mNo unknown SGID files present\e[39m";
fi

FILE='/etc/shadow';

RESULT=$(cat $FILE | awk -F: '($2 == "" ) { print $1 }');

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mSome accounts don't have a password, locking them...\e[39m";

	for ACCOUNT in $RESULT; do
		passwd -l "$ACCOUNT" >/dev/null 2>&1;
	done
else
	logger "\e[32mAll accounts have a password\e[39m";
fi

FILE='/etc/passwd';
RESULT='';

if grep '^+:' $FILE -q; then
	logger "\e[91mRemoving invalid password entries (/etc/passwd)\e[39m";

	RESULT=$(grep '^+:' $FILE);

	for LINE in $RESULT; do
		delete_line_in_file $FILE "$LINE";
	done
else
	logger "\e[32mAll accounts have a valid password entry format (/etc/passwd)\e[39m";
fi

FILE='/etc/shadow';
RESULT='';

if grep '^+:' $FILE -q; then
	logger "\e[91mRemoving invalid password entries (/etc/shadow)\e[39m";

	RESULT=$(grep '^+:' $FILE);

	for LINE in $RESULT; do
		delete_line_in_file $FILE "$LINE";
	done
else
	logger "\e[32mAll accounts have a valid password entry format (/etc/shadow)\e[39m";
fi

FILE='/etc/group'
RESULT=''

if grep '^+:' $FILE -q; then
	logger "\e[91mRemoving invalid group entries (/etc/group)\e[39m";

	RESULT=$(grep '^+:' $FILE);

	for LINE in $RESULT; do
		delete_line_in_file $FILE "$LINE"
	done
else
	logger "\e[32mAll accounts have a valid group entry format (/etc/group)\e[39m";
fi

FILE='/etc/passwd';
RESULT='';

RESULT=$(cat $FILE | awk -F: '($3 == 0 && $1!="root" ) { print $1 }');

for ACCOUNT in $RESULT; do
	if echo "$EXCEPTIONS" | grep -q "$ACCOUNT"; then
		RESULT=$(sed "s!$ACCOUNT!!" <<< "$RESULT");
	fi
done

if [[ ! -z "$RESULT" ]]; then
	logger "\e[91mSome accounts have UID 0\e[39m";
else
	logger "\e[32mOnly root and configured exceptions have UID 0\e[39m";
fi

ERRORS=0;

if [[ "`echo "$PATH" | grep :: `" != "" ]]; then
	ERRORS=$((ERRORS+1));
fi

if [[ "`echo "$PATH" | grep :$`" != "" ]]; then
	ERRORS=$((ERRORS+1));
fi

FORMATTED_PATH=$(echo "$PATH" | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g');

set -- "$FORMATTED_PATH";

while [[ "${1:-}" != "" ]]; do
	if [[ "$1" = "." ]]; then
		ERRORS=$((ERRORS+1));
	else
		if [[ -d $1 ]]; then
			dirperm=$(ls -ldH "$1" | cut -f1 -d" ");

			if [[ $(echo "$dirperm" | cut -c6 ) != "-" ]]; then
				ERRORS=$((ERRORS+1));
			fi

			if [[ $(echo "$dirperm" | cut -c9 ) != "-" ]]; then
				ERRORS=$((ERRORS+1));
			fi

			dirown=$(ls -ldH "$1" | awk '{print $3}');

			if [[ "$dirown" != "root" ]]; then
				ERRORS=$((ERRORS+1));
			fi

		else
			ERRORS=$((ERRORS+1));
		fi
	fi

	shift;
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[91mRoot path is secure\e[39m";
else
	logger "\e[32mRoot path is not secure\e[39m";
fi

ERRORS=0;
FILENAME=".rhosts";

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	for FILE in $DIR/$FILENAME; do
		if [ ! -h "$FILE" -a -f "$FILE" ]; then
			ERRORS=$((ERRORS+1));
		fi
	done
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32m$FILENAME is not present in any user's home directory\e[39m";
else
	logger "\e[91m$FILENAME is	present in at least one user's home directory\e[39m";
fi

ERRORS=0;
FILENAME='.netrc';

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	for FILE in $DIR/$FILENAME; do
		if [ ! -h "$FILE" -a -f "$FILE" ]; then
			ERRORS=$((ERRORS+1));
		fi
	done
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32m$FILENAME is not present in any user's home directory\e[39m";
else
	logger "\e[91m$FILENAME is	present in at least one user's home directory\e[39m";
fi

ERRORS=0;
FILENAME='.forward';

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
	for FILE in $DIR/$FILENAME; do
		if [ ! -h "$FILE" -a -f "$FILE" ]; then
			ERRORS=$((ERRORS+1));
		fi
	done
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32m$FILENAME is not present in any user's home directory\e[39m";
else
	logger "\e[91m$FILENAME is	present in at least one user's home directory\e[39m";
fi

ERRORS=0;

for GROUP in $(cut -s -d: -f4 /etc/passwd | sort -u); do
	if ! grep -q -P "^.*?:[^:]*:$GROUP:" /etc/group; then
		ERRORS=$((ERRORS+1));
	fi
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mpasswd and group groups are consistent\e[39m";
else
	logger "\e[91mpasswd and group groups are not consistent\e[39m";
fi

ERRORS=0;
RESULT=$(cat /etc/passwd | awk -F: '{ print $1 ":" $3 ":" $6 }');

d_IFS=$IFS;
IFS=$'\n';

for LINE in $RESULT; do
	USER=$(awk -F: {'print $1'} <<< "$LINE");
	USERID=$(awk -F: {'print $2'} <<< "$LINE");
	DIR=$(awk -F: {'print $3'} <<< "$LINE");

	if [ $USERID -ge 1000 -a ! -d "$DIR" -a $USER != "nfsnobody" -a $USER != "nobody" ]; then
		logger "\e[91mThe home directory ($DIR) of user $USER is not present\e[39m";

		ERRORS=$((ERRORS+1));
	fi
done

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mAll home directories are present\e[39m";
fi

ERRORS=0;
RESULT=$(cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} );

for LINE in $RESULT; do
	OCC_NUMBER=$(awk -F: {'print $1'} <<< "$LINE");
	USERID=$(awk -F: {'print $2'} <<< "$LINE");

	if [ $OCC_NUMBER -gt 1 ]; then
		USERS=$(awk -F: '($3 == n) { print $1 }' n="$USERID" /etc/passwd | xargs);
		ERRORS=$((ERRORS+1));

		logger "\e[91mDuplicate UID ($USERID): ${USERS}\e[39m";
		echo "Duplicate UID ($USERID): ${USERS}" >> $DUPLICATES_FILE;
	fi
done 

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mNo duplicate UIDs found\e[39m";
	echo "No duplicate UIDs" >> $DUPLICATES_FILE;
fi

ERRORS=0;
RESULT=$(cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} );

for LINE in $RESULT; do
	OCC_NUMBER=$(awk -F: {'print $1'} <<< "$LINE");
	GROUPID=$(awk -F: {'print $2'} <<< "$LINE");

	if [ $OCC_NUMBER -gt 1 ]; then
		USERS=$(awk -F: '($3 == n) { print $1 }' n="$GROUPID" /etc/passwd | xargs);
		ERRORS=$((ERRORS+1));

		logger "\e[91mDuplicate GID ($USERID): ${USERS}\e[39m";
		echo "Duplicate GID ($GROUPID): ${USERS}" >> $DUPLICATES_FILE;
	fi
done 

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mNo duplicate GIDs found\e[39m";
	echo "No duplicate GIDs" >> $DUPLICATES_FILE;
fi 

ERRORS=0;
RESULT=$(cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} );

for LINE in $RESULT; do
	OCC_NUMBER=$(awk -F: {'print $1'} <<< "$LINE");
	USERNAME=$(awk -F: {'print $2'} <<< "$LINE");

	if [ $OCC_NUMBER -gt 1 ]; then
		USERS=$(awk -F: '($3 == n) { print $1 }' n="$USERNAME" /etc/passwd | xargs);
		ERRORS=$((ERRORS+1));

		logger "\e[91mDuplicate username: $USERNAME\e[39m";
		echo "Duplicate username $USERNAME" >> $DUPLICATES_FILE;
	fi
done 

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mNo duplicate usernames found\e[39m";
	echo "No duplicate usernames" >> $DUPLICATES_FILE;
fi

ERRORS=0;
RESULT=$(cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} );

for LINE in $RESULT; do
	OCC_NUMBER=$(awk -F: {'print $1'} <<< "$LINE");
	GROUPNAME=$(awk -F: {'print $2'} <<< "$LINE");

	if [ $OCC_NUMBER -gt 1 ]; then
		USERS=$(awk -F: '($3 == n) { print $1 }' n="$GROUPNAME" /etc/passwd | xargs);
		ERRORS=$((ERRORS+1));
		
		logger "\e[91mDuplicate group name: $GROUPNAME\e[39m";
		echo "Duplicate groupname $GROUPNAME" >> $DUPLICATES_FILE;
	fi
done 

if [[ $ERRORS -eq 0 ]]; then
	logger "\e[32mNo duplicate group names found\e[39m";
	echo "No duplicate group names" >> $DUPLICATES_FILE;
fi

IFS=$d_IFS;

ERRORS=0;
FILEGROUP='/etc/group';
PATTERN='^shadow:x:[[:digit:]]+:';

file_does_pattern_exist $FILEGROUP "$PATTERN";

if [[ $FNRET -eq 0 ]]; then
	RESULT=$(grep -E "$PATTERN" $FILEGROUP | cut -d: -f4);
	GROUPID=$(getent group shadow | cut -d: -f3);

	if [[ ! -z "$RESULT" ]]; then
		logger "\e[91mSome users belong to the shadow group: $RESULT\e[39m";
	else
		logger "\e[32mNo user belongs to the shadow group\e[39m";
	fi

	RESULT=$(awk -F: '($4 == shadowid) { print $1 }' shadowid="$GROUPID" /etc/passwd);

	if [[ ! -z "$RESULT" ]]; then
		logger "\e[91mSome users have shadow id as their primary group: $RESULT\e[39m";
	else
		logger "\e[32mNo user has the shadow id as their primary group\e[39m";
	fi
else
	logger "\e[32mshadow group does not exist\e[39m";
fi

USER='root';
PATTERN='TMOUT=';
VALUE='600';
FILES_TO_SEARCH='/etc/bash.bashrc /etc/profile.d /etc/profile';
FILE='/etc/profile.d/CIS_99.1_timeout.sh';

SEARCH_RES=0
for FILE_SEARCHED in $FILES_TO_SEARCH; do
	if [[ $SEARCH_RES -eq 1 ]]; then break; fi

	if test -d "$FILE_SEARCHED"; then
		for file_in_dir in $(ls "$FILE_SEARCHED"); do
			file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN";

			if [[ $FNRET -eq 0 ]]; then
				SEARCH_RES=1;
				break;
			fi
		done
	else
		file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN";

		if [[ $FNRET -eq 0 ]]; then
			SEARCH_RES=1;
		fi
	fi
done

if [[ $SEARCH_RES -eq 0 ]]; then
	touch $FILE;
	chmod 644 $FILE >> $LOG_FILE 2>&1;
	append_to_file $FILE "$PATTERN$VALUE";
	append_to_file $FILE "readonly TMOUT";
	append_to_file $FILE "export TMOUT";
fi

USER='root';
PATTERN='ACTION=="add", SUBSYSTEMS=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"';
FILES_TO_SEARCH='/etc/udev/rules.d';
FILE='/etc/udev/rules.d/10-CIS_99.2_usb_devices.sh';

SEARCH_RES=0;

for FILE_SEARCHED in $FILES_TO_SEARCH; do
	if [[ $SEARCH_RES -eq 1 ]]; then break; fi

	if test -d $FILE_SEARCHED; then
		for file_in_dir in $(ls $FILE_SEARCHED); do
			file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN";

			if [[ $FNRET -eq 0 ]]; then
				SEARCH_RES=1;
				break;
			fi
		done
	else
		file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN";

		if [[ $FNRET -eq 0 ]]; then
			SEARCH_RES=1;
		fi
	fi
done

if [[ $SEARCH_RES -eq 0 ]]; then
	touch $FILE;
	chmod 644 $FILE >> $LOG_FILE 2>&1;
	append_to_file $FILE '

ACTION=="add", SUBSYSTEMS=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"

ACTION=="add", ATTR{bDeviceClass}=="09", TEST=="authorized", ATTR{authorized}="1"

ACTION=="add", ATTR{product}=="*[Kk]eyboard*", TEST=="authorized", ATTR{authorized}="1"

ACTION=="add", ATTR{product}=="*Thinnet TM*", TEST=="authorized", ATTR{authorized}="1"
';
fi

mkdir /etc/audit -p
touch /etc/audit/audit.rules

#################################
#
# OpenSSH settings
#
#################################

yes_no "Should OpenSSH be maintained?";

if [[ FNRET -eq 1 ]]; then
	# Update OpenSSH and apply safe configuration settings.

	MASTER_OPTIONS=(
		"X11Forwarding=no"
		"Ciphers=aes128-ctr,aes192-ctr,aes256-ctr"
		"PermitUserEnvironment=no"
		"PermitEmptyPasswords=no"
		"PermitRootLogin=no"
		"HostbasedAuthentication=no"
		"IgnoreRhosts=yes"
		"MaxAuthTries=4"
		"ClientAliveInterval=10"
		"ClientAliveCountMax=0"
		"AllowUsers="
		"AllowGroups=sshlogin"
		"DenyUsers=root"
		"DenyGroups=root"
		"UsePAM=yes"
		"Protocol=2"
		"RhostsRSAAuthentication=no"
		"RhostsAuthentication=no"
		"LoginGraceTime=1m"
		"SyslogFacility=AUTH"
		"MaxStartups=5"
		"PASS_WARN_AGE=7"
		"PASS_MIN_DAYS=7"
		"PASS_MAX_DAYS=90"
		"PASS_MIN_LEN=8"
	);

	logger "Updating OpenSSH...";
	apt_install openssh-server;
	apt_install login;

	MASTER_FILE=(
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/ssh/sshd_config"
		"/etc/login.defs"
		"/etc/login.defs"
		"/etc/login.defs"
		"/etc/login.defs"
	);

	logger "Applying OpenSSH settings... (0/${#MASTER_FILE[@]})" 1;

	for i in ${!MASTER_FILE[@]}; do
		OPTIONS=${MASTER_OPTIONS[$i]};
		FILE=${MASTER_FILE[$i]};

		for SSH_OPTION in $OPTIONS; do
			SSH_PARAM=$(echo "$SSH_OPTION" | cut -d= -f 1);
			SSH_VALUE=$(echo "$SSH_OPTION" | cut -d= -f 2);
			PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE";
			file_does_pattern_exist "$FILE" "$PATTERN";

			if [[ $FNRET -ne 0 ]]; then
				file_does_pattern_exist "$FILE" "^$SSH_PARAM";

				if [[ $FNRET -ne 0 ]]; then
					append_to_file "$FILE" "$SSH_PARAM $SSH_VALUE";
				else
					replace_in_file "$FILE" "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE";
				fi

				/etc/init.d/ssh reload > /dev/null 2>&1;
			fi

			logger "Applying OpenSSH settings... ("$(($i + 1))"/${#MASTER_FILE[@]})" 1;
		done
	done

	echo "";
else
	# OpenSSH not required, remove it.

	logger "Removing OpenSSH...";
	apt_purge openssh-server;
fi

#################################
#
# Apache2 settings
#
#################################

yes_no "Should Apache2 be maintained?";

if [[ FNRET -eq 1 ]]; then
	# Update Apache2 and apply safe configuration settings.

	apt_install apache2;

	echo "";
	logger "Configuring Apache2...";
	echo "ServerSignature Off" >> /etc/apache2/apache2.conf;
	echo "ServerTokens Prod" >> /etc/apache2/apache2.conf;

	service apache2 restart >> $LOG_FILE 2>&1;
else
	# Apache2 not required, remove it.

	logger "Removing Apache2...";
	apt_purge apache2;
fi

#################################
#
# nginx settings
#
#################################

yes_no "Should nginx be maintained?";

if [[ FNRET -eq 1 ]]; then
	# Update nginx and apply safe configuration settings.

	apt_install nginx;

	sed -i "/server_tokens/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/client_body_buffer_size/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/client_header_buffer_size/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/client_max_body_size/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/large_client_header_buffers/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/error_log/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/ssl_protocols/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;
	sed -i "/ssl_prefer_server_ciphers/d" /etc/nginx/nginx.conf >> $LOG_FILE 2>&1;

	echo "server_tokens off" >> /etc/nginx/nginx.conf;
	echo "client_body_buffer_size 1k" >> /etc/nginx/nginx.conf;
	echo "client_header_buffer_size 1k" >> /etc/nginx/nginx.conf;
	echo "client_max_body_size 1k" >> /etc/nginx/nginx.conf;
	echo "large_client_header_buffers 2 1k" >> /etc/nginx/nginx.conf;
	echo "error_log logs/error.log crit;" >> /etc/nginx/nginx.conf;
	echo "add_header X-Frame-Options \"SAMEORIGIN\";" >> /etc/nginx/nginx.conf;
	echo "add_header Strict-Transport-Security \"max-age=31536000; includeSubdomains; preload\";" >> /etc/nginx/nginx.conf;
	echo "add_header Content-Security-Policy \"default-src 'self' http: https: data: blob: 'unsafe-inline'\" always;" >> /etc/nginx/nginx.conf;
	echo "add_header X-XSS-Protection "1; mode=block";" >> /etc/nginx/nginx.conf;
	echo "ssl_protocols TLSv1.2 TLSv1.3;" >> /etc/nginx/nginx.conf;
	echo "ssl_prefer_server_ciphers on;" >> /etc/nginx/nginx.conf;

	echo "";
else
	# nginx not required, remove it.

	logger "Removing nginx...";
	apt_purge nginx;
fi

#################################
#
# Samba settings
#
#################################

yes_no "Should Samba be maintained?";

if [[ FNRET -eq 1 ]]; then
	# Update Samba and apply safe configuration settings.

	apt_install samba;

	echo "";
else
	# Samba not required, remove it.

	logger "Removing Samba...";
	service samba stop >> $LOG_FILE 2>&1;
	apt_purge samba;
fi

#################################
#
# vsftpd settings
#
#################################

yes_no "Should vsftpd be maintained?";

if [[ FNRET -eq 1 ]]; then
	# Update Samba and apply safe configuration settings.

	apt_install vsftpd;

	# TODO: vsftpd config

	echo "";
else
	# vsftpd not required, remove it.

	logger "Removing vsftpd...";
	service vsftpd stop >> $LOG_FILE 2>&1;
	apt_purge vsftpd;
fi

#################################
#
# Use open-source scanners
#
#################################

# RKHunter
logger "Scanning with RKHunter, this may take a while...";
rkhunter --update >> /dev/null 2>&1;
rkhunter --propupd >> /dev/null 2>&1;
rkhunter --check --nocolors --skip-keypress >> rkhunter.txt 2>&1;

# logger "Scanning with Tiger, this may take a while...";
# tiger -e > tiger.txt 2>&1;

# logger "Scanning with ClamAV, this may take a while...";
# clamscan --remove --quiet -oir / > clam.txt 2>&1;

logger "Running LogWatch...";
logwatch >> $LOG_FILE 2>&1;

logger "Setting up AppArmor...";
apparmor_status > $APPARMOR_FILE 2>&1;

# # create a backup of iptables and ip6tables
# mkdir iptables >> $LOG_FILE 2>&1;
# iptables-save > iptables/rules_v4.backup >> $LOG_FILE 2>&1;
# ip6tables-save > iptables/rules_v6.backup >> $LOG_FILE 2>&1;
# 
# NETWORK_INTERFACE=$(route | awk '/^default/{print $NF}');
# IPTABLES_SETTINGS=(
# 	"-A INPUT -p tcp --syn --dport 22 -m connlimit --connlimit-above 3 -j REJECT"
# 	"-p tcp --syn --dport 80 -m connlimit --connlimit-above 20 --connlimit-mask 24 -j DROP"
# 	"-t nat -F"
# 	"-t mangle -F"
# 	"-t nat -X"
# 	"-t mangle -X"
# 	"-F"
# 	"-X"
# 	"-P INPUT DROP"
# 	"-P FORWARD DROP"
# 	"-P OUTPUT ACCEPT"
# 	"-A INPUT -s 127.0.0.0/8 -i $NETWORK_INTERFACE -j DROP"
# 	"-A INPUT -s 0.0.0.0/8 -j DROP"
# 	"-A INPUT -s 100.64.0.0/10 -j DROP"
# 	"-A INPUT -s 169.254.0.0/16 -j DROP"
# 	"-A INPUT -s 192.0.0.0/24 -j DROP"
# 	"-A INPUT -s 192.0.2.0/24 -j DROP"
# 	"-A INPUT -s 198.18.0.0/15 -j DROP"
# 	"-A INPUT -s 198.51.100.0/24 -j DROP"
# 	"-A INPUT -s 203.0.113.0/24 -j DROP"
# 	"-A INPUT -s 224.0.0.0/3 -j DROP"
# 	"-A OUTPUT -d 127.0.0.0/8 -o $NETWORK_INTERFACE -j DROP"
# 	"-A OUTPUT -d 0.0.0.0/8 -j DROP"
# 	"-A OUTPUT -d 100.64.0.0/10 -j DROP"
# 	"-A OUTPUT -d 169.254.0.0/16 -j DROP"
# 	"-A OUTPUT -d 192.0.0.0/24 -j DROP"
# 	"-A OUTPUT -d 192.0.2.0/24 -j DROP"
# 	"-A OUTPUT -d 198.18.0.0/15 -j DROP"
# 	"-A OUTPUT -d 198.51.100.0/24 -j DROP"
# 	"-A OUTPUT -d 203.0.113.0/24 -j DROP"
# 	"-A OUTPUT -d 224.0.0.0/3 -j DROP"
# 	"-A OUTPUT -s 127.0.0.0/8 -o $NETWORK_INTERFACE -j DROP"
# 	"-A OUTPUT -s 0.0.0.0/8 -j DROP"
# 	"-A OUTPUT -s 100.64.0.0/10 -j DROP"
# 	"-A OUTPUT -s 169.254.0.0/16 -j DROP"
# 	"-A OUTPUT -s 192.0.0.0/24 -j DROP"
# 	"-A OUTPUT -s 192.0.2.0/24 -j DROP"
# 	"-A OUTPUT -s 198.18.0.0/15 -j DROP"
# 	"-A OUTPUT -s 198.51.100.0/24 -j DROP"
# 	"-A OUTPUT -s 203.0.113.0/24 -j DROP"
# 	"-A OUTPUT -s 224.0.0.0/3 -j DROP"
# 	"-A INPUT -d 127.0.0.0/8 -i $NETWORK_INTERFACE -j DROP"
# 	"-A INPUT -d 0.0.0.0/8 -j DROP"
# 	"-A INPUT -d 100.64.0.0/10 -j DROP"
# 	"-A INPUT -d 169.254.0.0/16 -j DROP"
# 	"-A INPUT -d 192.0.0.0/24 -j DROP"
# 	"-A INPUT -d 192.0.2.0/24 -j DROP"
# 	"-A INPUT -d 198.18.0.0/15 -j DROP"
# 	"-A INPUT -d 198.51.100.0/24 -j DROP"
# 	"-A INPUT -d 203.0.113.0/24 -j DROP"
# 	"-A INPUT -d 224.0.0.0/3 -j DROP"
# 	"-A INPUT -i lo -j ACCEPT"
# 	"-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
# 	"-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
# 	"-A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
# 	"-A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT"
# 	"-A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
# 	"-A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
# 	"-A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
# 	"-A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
# 	"-A OUTPUT -o lo -j ACCEPT"
# 	"-P OUTPUT DROP"
# );
# 
# logger "Configuring iptables... (0/${#IPTABLES_SETTINGS[@]})" 1;
# 
# for i in ${!IPTABLES_SETTINGS[@]}; do
# 	SETTING=${IPTABLES_SETTINGS[$i]};
# 	logger "Configuring iptables... ("$(($i + 1))"/${#IPTABLES_SETTINGS[@]}) - $SETTING" 1;
# 
# 	iptables $SETTING >> $LOG_FILE 2>&1;
# done
# 
# IP6TABLES_SETTINGS=(
# 	"-t nat -F"
# 	"-t mangle -F"
# 	"-t nat -X"
# 	"-t mangle -X"
# 	"-F"
# 	"-X"
# 	"-P INPUT DROP"
# 	"-P FORWARD DROP"
# 	"-P OUTPUT DROP"
# );
# 
# logger "Configuring ip6tables... (0/${#IPTABLES_SETTINGS[@]})" 1;
# 
# for i in ${!IPTABLES_SETTINGS[@]}; do
# 	SETTING=${IPTABLES_SETTINGS[$i]};
# 	logger "Configuring ip6tables... ("$(($i + 1))"/${#IPTABLES_SETTINGS[@]}) - $SETTING" 1;
# 
# 	iptables $SETTING >> $LOG_FILE 2>&1;
# done
# 
# logger "Configured ${#IPTABLES_SETTINGS[@]} settings for iptables";
# 
# # save  configuration settings
# mkdir /etc/iptables/
# iptables-save > /etc/iptables/rules.v4
# ip6tables-save > /etc/iptables/rules.v6

# Update the distribution
logger "Running full-upgrade..."

apt_update;
apt_full_upgrade;
apt_autoremove;
apt_autoclean;

function display_time {
	local T=$1
	local M=$((T/60%60))
	local S=$((T%60))
	(( $M > 0 )) && printf '%dm ' $M
	printf '%ds\n' $S
}

logger "Restarting services...";
sysctl -p >> $LOG_FILE 2>&1;
ufw --force enable >> $LOG_FILE 2>&1;
service ssh restart >> $LOG_FILE 2>&1;

echo "";
printf "  This script executed in "
display_time $SECONDS
echo "";
echo "  Made by Matteo Polak";
echo "";
