# FogWatch : détection collaborative d'attaques distribuées

## Prérequis
Ubuntu 24.04, Tailscale (même tailnet), Suricata 8.0.7 (même version sur les 3 sites).

## Installation d'un site
1. Hostname unique : `sudo hostnamectl set-hostname site-X` puis `sudo tailscale set --hostname=site-X`
2. `git clone <dépôt> && cd ids-fog`
3. `bash detection/install-suricata.sh`
4. `bash response-agent/setup-nft.sh`
5. K3s : serveur sur site-A, agent sur B et C (voir commandes dans docs/)
6. `docker build -t fog-agent:v1 fog-agent/` puis import dans K3s

## Pièges connus
- Les règles vont dans `/var/lib/suricata/rules/`, pas dans `/etc/`.
- `HOME_NET` = IP de la VM en /32, différent sur chaque site.
- Hostname unique avant d'installer K3s.
- Ne pas activer Tailscale SSH.
- Ne jamais committer le token K3s ni les logs.

## Règle d'or
Aucun réglage manuel sur une VM : tout passe par Git

