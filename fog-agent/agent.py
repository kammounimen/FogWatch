import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

EVE_PATH = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
SITE_ID = os.environ.get("SITE_ID", "A")
WINDOW_SECONDS = int(os.environ.get("WINDOW_SECONDS", "30"))
LOCAL_ALERT_THRESHOLD = int(os.environ.get("LOCAL_ALERT_THRESHOLD", "10"))
MQTT_BROKER = os.environ.get("MQTT_BROKER")  # vide = on affiche seulement

# On ne compte QUE la règle "SSH connection attempt" (1 SYN = 1 tentative).
# La règle 9000002 (seuil Suricata) se déclenche sur le même paquet : la compter doublerait la tentative.
ATTEMPT_SID = 9000001
EVENT_TYPE = "ssh_fail"  # nom à valider avec l'équipe (correlator)


def tail_file(path):
    """Lit les nouvelles lignes. Renvoie None quand il n'y a rien, pour que la fenêtre puisse se fermer."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            # fichier vidé (truncate) ou tourné : on repart du début
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


def main():
    client = make_mqtt_client()
    counts = defaultdict(int)
    window_start = time.time()

    for line in tail_file(EVE_PATH):
        if line:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {}
            alert = event.get("alert", {})
            if event.get("event_type") == "alert" and alert.get("signature_id") == ATTEMPT_SID:
                src_ip = event.get("src_ip")
                if src_ip:
                    counts[src_ip] += 1

        now = time.time()
        if now - window_start >= WINDOW_SECONDS:
            for ip, count in counts.items():
                payload = {
                    "site_id": SITE_ID,
                    "src_ip": ip,
                    "type": EVENT_TYPE,
                    "count": count,
                    "window_start": datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat(),
                    "window_end": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                    "local_alert": count >= LOCAL_ALERT_THRESHOLD,
                }
                print(json.dumps(payload), flush=True)
                if client:
                    client.publish(f"fog/{SITE_ID}/events", json.dumps(payload))
            counts.clear()
            window_start = now


if __name__ == "__main__":
    main()
