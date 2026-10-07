import json
import time
import os
from collections import defaultdict
from datetime import datetime, timezone

EVE_PATH = "/var/log/suricata/eve.json"
SITE_ID = os.environ.get("SITE_ID", "A")
WINDOW_SECONDS = 30

def tail_file(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def main():
    counts = defaultdict(int)
    window_start = time.time()

    for line in tail_file(EVE_PATH):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        src_ip = event.get("src_ip")
        if src_ip:
            counts[src_ip] += 1

        if time.time() - window_start >= WINDOW_SECONDS:
            for ip, count in counts.items():
                payload = {
                    "site_id": SITE_ID,
                    "src_ip": ip,
                    "type": "ssh_fail",
                    "count": count,
                    "window_start": datetime.fromtimestamp(window_start, tz=timezone.utc).isoformat(),
                    "window_end": datetime.now(timezone.utc).isoformat(),
                    "local_alert": count >= 10
                }
                print(json.dumps(payload))
                # TODO : remplacer par client.publish(f"fog/{SITE_ID}/events", json.dumps(payload))

            counts.clear()
            window_start = time.time()

if __name__ == "__main__":
    main()
