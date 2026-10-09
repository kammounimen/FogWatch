set -e
sudo apt install -y nftables
sudo systemctl enable --now nftables
sudo nft add table inet filter
sudo nft add chain inet filter input '{ type filter hook input priority 0 ; }'

