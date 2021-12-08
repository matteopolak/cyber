# create user 'ben'
useradd -m ben;

yes 'root' | passwd ben;

# install 'openssh-server' package
apt install openssh-server -y;

# start the openssh server
service ssh start;