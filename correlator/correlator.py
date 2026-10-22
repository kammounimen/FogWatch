import json
import time
import os
from datetime import datetime, timezone
import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
MODE = os.environ.get("MODE", "collaborative")        # isolated | collaborative
GLOBAL_THRESHOLD = int(os.environ.get("GLOBAL_THRESHOLD", "10"))
MIN_SITES = int(os.environ.get("MIN_SITES", "2"))
STALE_SECONDS = int(os.environ.get("STALE_SECONDS", "15"))   # 3 x REPORT_SECONDS de l'agent
BLOCK_TTL_SECONDS = int(os.environ.get("BLOCK_TTL_SECONDS", "300"))
ALL_SITES = ["A", "B", "C"]
ALLOWLIST = {"100.103.105.18", "100.75.234.57"}      # master + ta machine d'admin

# { src_ip: { "A": (timestamp, count), "B": (timestamp, count) } }
latest = {}
already_blocked = {}

try:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="correlator")  # paho 2.x
except AttributeError:
    client = mqtt.Client(client_id="correlator")                                    # paho 1.x


def check_correlation(ip):
    now = time.time()
    sites = latest.get(ip, {})
    # on oublie les sites silencieux ou à 0
    for site in list(sites):
        ts, c = sites[site]
        if c == 0 or now - ts > STALE_SECONDS:
            del sites[site]
    if not sites:
        latest.pop(ip, None)
        return

    sites_touched = list(sites)
    total = sum(c for _, c in sites.values())
    print(f"[DEBUG] {ip}: sites={sites_touched}, total={total}", flush=True)

    if MODE == "isolated":
        return
    if total < GLOBAL_THRESHOLD or len(sites_touched) < MIN_SITES:
        return
    if ip in ALLOWLIST:
        print(f"[INFO] {ip} dans l'allowlist, pas de blocage", flush=True)
        return
    if now - already_blocked.get(ip, 0) < BLOCK_TTL_SECONDS:
        return

    already_blocked[ip] = now
    alert = {"src_ip": ip, "sites_touched": sites_touched, "total_count": total,
             "detected_at": datetime.now(timezone.utc).isoformat(), "mode": MODE}
    client.publish("fog/global/alerts", json.dumps(alert), qos=1)
    print(f"[ALERTE GLOBALE] {alert}", flush=True)

    for site in ALL_SITES:
        order = {"src_ip": ip, "ttl_seconds": BLOCK_TTL_SECONDS}
        client.publish(f"fog/{site}/block", json.dumps(order), qos=1)
        print(f"[BLOCAGE] fog/{site}/block pour {ip}", flush=True)


def on_connect(client, userdata, flags, rc, properties=None):
    print(f"Connecté au broker, code={rc}", flush=True)
    client.subscribe("fog/+/events")


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    site, ip = data.get("site_id"), data.get("src_ip")
    if not site or not ip:
        return
    latest.setdefault(ip, {})[site] = (time.time(), data.get("count", 0))   # REMPLACE, n'additionne plus
    check_correlation(ip)


client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER_HOST, 1883, keepalive=60)
print(f"Correlator démarré en mode: {MODE}", flush=True)
client.loop_forever()


