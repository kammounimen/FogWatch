"""
response-agent : bloque une IP source quand le corrélateur le demande.

Écoute le topic MQTT  fog/<SITE_ID>/block  ; le message est soit un JSON {"ip": "1.2.3.4"}
(ou {"src_ip": "1.2.3.4"}), soit simplement l'adresse IP en texte.

Le blocage utilise sa PROPRE table nftables ("fogwatch") : un set d'adresses avec expiration
automatique (BLOCK_SECONDS), donc rien de permanent et pas de règles en double.

Variables d'environnement :
  SITE_ID          A, B ou C (topic écouté : fog/<SITE_ID>/block)
  MQTT_BROKER      IP du broker (ex. 100.103.105.18). Elle est ajoutée d'office à l'allowlist.
  ALLOWLIST        IP à ne JAMAIS bloquer, séparées par des virgules
                   (master, sites A/B/C, ta machine d'administration). NE JAMAIS y mettre l'attaquant.
  BLOCK_SECONDS    durée du blocage en secondes (300 par défaut)
  DRY_RUN=1        n'exécute pas nft, affiche seulement ce qui serait fait (pour tester)

Usage :
  sudo SITE_ID=B MQTT_BROKER=100.103.105.18 ALLOWLIST=100.103.105.18,100.75.234.57 python3 respond.py
  sudo ALLOWLIST=... python3 respond.py --block 203.0.113.9     # test manuel, sans MQTT
Pour tout débloquer :  sudo nft flush set inet fogwatch blocked
"""
import ipaddress
import json
import os
import subprocess
import sys

SITE_ID = os.environ.get("SITE_ID", "A")
MQTT_BROKER = os.environ.get("MQTT_BROKER")
BLOCK_SECONDS = int(os.environ.get("BLOCK_SECONDS", "300"))
DRY_RUN = os.environ.get("DRY_RUN") == "1"
ALLOWLIST = {x.strip() for x in os.environ.get("ALLOWLIST", "").split(",") if x.strip()}
if MQTT_BROKER:
    ALLOWLIST.add(MQTT_BROKER)

TABLE = "fogwatch"


def nft(*args):
    """Exécute une commande nft. Retourne True si elle a réussi."""
    if DRY_RUN:
        print("[DRY_RUN] nft", " ".join(args), flush=True)
        return True
    result = subprocess.run(["nft", *args], capture_output=True, text=True)
    if result.returncode != 0:
        print("Erreur nft :", result.stderr.strip(), flush=True)
        return False
    return True


def setup_firewall():
    """Crée la table, le set et la règle (peut être relancé sans créer de doublon)."""
    nft("add", "table", "inet", TABLE)
    nft("add", "set", "inet", TABLE, "blocked", "{ type ipv4_addr; flags timeout; }")
    nft("add", "chain", "inet", TABLE, "input", "{ type filter hook input priority -10; }")
    nft("flush", "chain", "inet", TABLE, "input")   # notre chaîne seulement
    nft("add", "rule", "inet", TABLE, "input", "ip", "saddr", "@blocked", "drop")


def block_ip(raw_ip):
    """Bloque une IP après vérifications. Retourne True si elle a été bloquée."""
    try:
        ip = ipaddress.ip_address(str(raw_ip).strip())
    except ValueError:
        print(f"Adresse invalide ignorée : {raw_ip!r}", flush=True)
        return False
    if ip.version != 4:
        print(f"IP {ip} ignorée (seul IPv4 est géré)", flush=True)
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        print(f"IP {ip} ignorée (adresse spéciale)", flush=True)
        return False
    if str(ip) in ALLOWLIST:
        print(f"IP {ip} dans l'allowlist : PAS de blocage", flush=True)
        return False
    ok = nft("add", "element", "inet", TABLE, "blocked", f"{{ {ip} timeout {BLOCK_SECONDS}s }}")
    if ok:
        print(f"IP {ip} bloquée pour {BLOCK_SECONDS}s sur le site {SITE_ID}", flush=True)
    return ok


def extract_ip(payload_bytes):
    """Accepte {"ip": ...}, {"src_ip": ...} ou une IP en texte brut."""
    text = payload_bytes.decode("utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(data, dict):
        return data.get("ip") or data.get("src_ip")
    return data if isinstance(data, str) else None


def on_message(client, userdata, msg):
    ip = extract_ip(msg.payload)
    if ip:
        block_ip(ip)
    else:
        print(f"Message sans IP sur {msg.topic} : {msg.payload[:80]!r}", flush=True)


def run_mqtt():
    if not MQTT_BROKER:
        sys.exit("MQTT_BROKER non défini : impossible d'écouter les ordres de blocage")
    import paho.mqtt.client as mqtt
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)  # paho-mqtt >= 2
    except AttributeError:
        client = mqtt.Client()                                   # paho-mqtt 1.x
    topic = f"fog/{SITE_ID}/block"

    def on_connect(client, userdata, flags, *args):
        client.subscribe(topic)                                  # se réabonne aussi après une reconnexion
        print(f"Connecté au broker {MQTT_BROKER}, écoute de {topic}", flush=True)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, 1883)
    client.loop_forever()


def main():
    print(f"response-agent site {SITE_ID} | allowlist : {sorted(ALLOWLIST) or 'VIDE (attention)'}", flush=True)
    setup_firewall()
    if len(sys.argv) == 3 and sys.argv[1] == "--block":
        block_ip(sys.argv[2])
        return
    run_mqtt()


if __name__ == "__main__":
    main()


