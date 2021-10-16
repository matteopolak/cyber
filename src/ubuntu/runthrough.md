## Detailed
| Command | Explanation |
| --- | --- |
| `passwd -l root` | Disables the root account |
| `echo "allow-guest=false" >> /etc/lightdm/lightdm.conf` | Disables the guest account |
| `ufw enable` | Enables Ubuntu's [Uncomplicated Firewall](https://wiki.ubuntu.com/UncomplicatedFirewall) |
| `apt-get update` | Updates the APT package cache |
| `apt-get upgrade` | Upgrades all APT packages |