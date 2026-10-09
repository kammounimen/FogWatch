# Usage, depuis la racine du dépôt : bash detection/install-suricata.sh
set -e

MY_IP=$(tailscale ip -4)
CONF=/etc/suricata/suricata.yaml
echo "IP Tailscale de cette VM : $MY_IP"

# 1. Règles : toujours copiées depuis Git
sudo install -m 644 detection/local.rules /var/lib/suricata/rules/local.rules

# 2. HOME_NET = cette machine uniquement
sudo sed -i "s|^\(\s*HOME_NET:\).*|\1 \"[${MY_IP}/32]\"|" $CONF

# 3. Interface d'écoute : tailscale0 (première interface af-packet)
sudo sed -i '/^af-packet:/,/^[^ #-]/ s/- interface: \(eth\|en\)[a-z0-9]*/- interface: tailscale0/' $CONF

# 4. Déclarer local.rules (une seule fois)
grep -q "^\s*- local.rules" $CONF || sudo sed -i '/^rule-files:/a\  - local.rules' $CONF

# 5. Vérifications
echo "--- Vérification de la config ---"
grep -n "HOME_NET:" $CONF | head -3
grep -n "interface: tailscale0" $CONF
grep -n -A3 "^rule-files:" $CONF

sudo suricata -T -c $CONF
sudo systemctl restart suricata
sudo systemctl enable suricata
sleep 3
sudo grep -i "signatures processed" /var/log/suricata/suricata.log | tail -1

