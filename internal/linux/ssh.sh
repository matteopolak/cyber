# create user 'ben'
useradd -m ben;

yes 'root' | passwd ben;

# install 'openssh-server' package
apt install openssh-server -y;

# whitelist ssh (port 22)
ufw allow ssh;

# start the openssh server
service ssh start;