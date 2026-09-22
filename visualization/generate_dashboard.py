import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

EVE_FILE = Path(r"C:\Program Files\Suricata\log\eve.json")
OUTPUT_FILE = Path(r"C:\CodeAlpha_NetworkIntrusionDetectionSystem\visualization\alert_summary.png")

alerts = []

with EVE_FILE.open("r", encoding="utf-8") as f:
    for line in f:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") == "alert":
            alerts.append(event)

if not alerts:
    print("No alert events found in eve.json.")
    raise SystemExit(0)

signatures = Counter(
    event.get("alert", {}).get("signature", "Unknown")
    for event in alerts
)

labels = list(signatures.keys())
values = list(signatures.values())

plt.figure(figsize=(10, 6))
plt.bar(labels, values)
plt.title("Suricata IDS Alert Summary")
plt.xlabel("Alert Signature")
plt.ylabel("Number of Alerts")
plt.xticks(rotation=20, ha="right")
plt.tight_layout()
plt.savefig(OUTPUT_FILE, dpi=150)
plt.show()

print(f"Total alerts: {len(alerts)}")
print(f"Dashboard saved to: {OUTPUT_FILE}")
