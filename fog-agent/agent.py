"""
fog-agent (version fenêtre glissante).

Différences avec la version à fenêtres fixes :
  - Les tentatives sont comptées sur une fenêtre GLISSANTE de WINDOW_SECONDS par IP source.
    Une rafale n'est plus coupée en deux par une frontière de fenêtre.
  - L'alerte locale part IMMÉDIATEMENT à la tentative qui atteint le seuil
    (la 5e avec le seuil par défaut), sans attendre la fin d'une fenêtre.
  - Des "observations" sont publiées toutes les REPORT_SECONDS pour le corrélateur : elles
    donnent, par IP, le nombre de tentatives dans les WINDOW_SECONDS dernières secondes
    (même sous le seuil, c'est ce qui permet la détection collaborative).
    Quand l'IP n'a plus de tentative dans la fenêtre, une dernière observation count=0 est envoyée.

Variables d'environnement :
  SITE_ID, EVE_PATH, MQTT_BROKER (vide = on affiche seulement),
  WINDOW_SECONDS (30), LOCAL_ALERT_THRESHOLD (5), REPORT_SECONDS (5)
Les 3 sites doivent utiliser les mêmes valeurs de WINDOW_SECONDS et LOCAL_ALERT_THRESHOLD.
"""
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
SITE_ID = os.environ.get("SITE_ID", "A")
WINDOW_SECONDS = float(os.environ.get("WINDOW_SECONDS", "30"))
LOCAL_ALERT_THRESHOLD = int(os.environ.get("LOCAL_ALERT_THRESHOLD", "5"))
REPORT_SECONDS = float(os.environ.get("REPORT_SECONDS", "5"))
MQTT_BROKER = os.environ.get("MQTT_BROKER")  # vide = on affiche seulement

# On ne compte QUE la règle "SSH connection attempt" (flags:S : 1 SYN = 1 tentative).
ATTEMPT_SID = 9000001
EVENT_TYPE = "ssh_fail"


def tail_file(path):
    """Lit les nouvelles lignes. Renvoie None quand il n'y a rien, pour que les minuteries tournent."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            # fichier vidé (truncate) : on repart du début
            if os.fstat(f.fileno()).st_size < f.tell():
                f.seek(0)
            line = f.readline()
            if not line:
                time.sleep(0.5)
                yield None
                continue
            yield line


def make_mqtt_client():
    if not MQTT_BROKER:
        return None
    import paho.mqtt.client as mqtt
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)  # paho-mqtt >= 2
    except AttributeError:
        client = mqtt.Client()  # paho-mqtt 1.x
    client.connect(MQTT_BROKER, 1883)
    client.loop_start()
    return client


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def prune(stamps, now):
    """Retire les tentatives sorties de la fenêtre glissante."""
    while stamps and now - stamps[0] > WINDOW_SECONDS:
        stamps.popleft()


def build_payload(ip, stamps, now, kind):
    count = len(stamps)
    return {
        "site_id": SITE_ID,
        "src_ip": ip,
        "type": EVENT_TYPE,
        "count": count,                                   # tentatives dans les WINDOW_SECONDS dernières secondes
        "window_start": iso(stamps[0] if stamps else now),
        "window_end": iso(now),
        "local_alert": count >= LOCAL_ALERT_THRESHOLD,
        "kind": kind,                                     # "local_alert" (immédiate) ou "observation" (périodique)
    }


def emit(client, payload):
    print(json.dumps(payload), flush=True)
    if client:
        client.publish(f"fog/{SITE_ID}/events", json.dumps(payload))


def main():
    client = make_mqtt_client()
    attempts = defaultdict(deque)   # ip -> horodatages des tentatives dans la fenêtre
    alerted_until = {}              # ip -> pas de nouvelle alerte locale avant cet instant
    active = set()                  # ips à surveiller dans les observations périodiques
    last_report = time.time()

    for line in tail_file(EVE_PATH):
        now = time.time()

        if line:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {}
            alert = event.get("alert", {})
            if event.get("event_type") == "alert" and alert.get("signature_id") == ATTEMPT_SID:
                ip = event.get("src_ip")
                if ip:
                    stamps = attempts[ip]
                    stamps.append(now)
                    prune(stamps, now)
                    active.add(ip)
                    # alerte immédiate à la tentative qui atteint le seuil
                    if len(stamps) >= LOCAL_ALERT_THRESHOLD and now >= alerted_until.get(ip, 0):
                        emit(client, build_payload(ip, stamps, now, "local_alert"))
                        alerted_until[ip] = now + WINDOW_SECONDS

        if now - last_report >= REPORT_SECONDS:
            for ip in list(active):
                stamps = attempts[ip]
                prune(stamps, now)
                emit(client, build_payload(ip, stamps, now, "observation"))
                if not stamps:              # dernière observation (count=0) envoyée : on oublie cette IP
                    active.discard(ip)
                    attempts.pop(ip, None)
                    alerted_until.pop(ip, None)
            last_report = now


if __name__ == "__main__":
    main()


