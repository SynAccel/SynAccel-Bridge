from datetime import datetime, timezone, timedelta

# Track the last alert time per source to avoid spamming
last_alert_time = {}

def safe_details(event):
    """Ensure details is always a dict, even if missing or malformed."""
    d = event.get("details")
    return d if isinstance(d, dict) else {}

def correlate_events(events):
    """
    Analyze recent events for abnormal patterns.
    Returns a list of structured alert dictionaries.
    """
    alerts = []
    now = datetime.now(timezone.utc)

    # --- Parameters ---
    INTRUSION_THRESHOLD = 3            # How many intrusions before alert
    COOLDOWN_PERIOD = timedelta(seconds=60)  # Wait 60s before re-alerting same source
    WINDOW = timedelta(seconds=30)     # Analyze events in the past 30s

    # --- Filter only recent events ---
    recent_window = [
        e for e in events
        if now - datetime.fromisoformat(e["timestamp"]) <= WINDOW
    ]

    # --- Rule 1: Repeated intrusions from the same source ---
    intrusion_counts = {}
    for e in recent_window:
        if e.get("type") == "intrusion":
            intrusion_counts[e["source"]] = intrusion_counts.get(e["source"], 0) + 1

    for src, count in intrusion_counts.items():
        if count >= INTRUSION_THRESHOLD:
            if src not in last_alert_time or now - last_alert_time[src] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": src,
                    "rule_id": 1,
                    "category": "intrusion",
                    "type": "intrusion_spike",
                    "severity": "high",
                    "message": f"{count} intrusion events from {src} within 30 seconds"
                })
                last_alert_time[src] = now

    # --- Rule 2: Motion followed by access_denied from same source ---
    for i in range(len(recent_window) - 1):
        current = recent_window[i]
        nxt = recent_window[i + 1]
        if (
            current.get("type") == "motion"
            and nxt.get("type") == "access_denied"
            and current.get("source") == nxt.get("source")
        ):
            src = current["source"]
            if src not in last_alert_time or now - last_alert_time[src] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": src,
                    "rule_id": 2,
                    "category": "access_control",
                    "type": "sequence_alert",
                    "severity": "medium",
                    "message": f"Motion followed by access_denied on {src}"
                })
                last_alert_time[src] = now

    # --- Rule 3: LIDAR failure while vehicle is moving ---
    for e in recent_window:
        details = safe_details(e)
        source = e.get("source")
        lidar = details.get("lidar_status")
        speed = details.get("speed_kph", 0)

        if lidar == "FAIL" and speed > 5:
            if source not in last_alert_time or now - last_alert_time[source] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": source,
                    "rule_id": 3,
                    "category": "sensor",
                    "type": "sensor_failure",
                    "severity": "high",
                    "message": f"LIDAR failure detected while vehicle {source} moving at {speed} kph"
                })
                last_alert_time[source] = now

    # --- Rule 4: Low battery warning (vehicles) ---
    for e in recent_window:
        details = safe_details(e)
        source = e.get("source")
        battery = details.get("battery_percent")

        if isinstance(battery, (int, float)) and battery < 25:
            if source not in last_alert_time or now - last_alert_time[source] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": source,
                    "rule_id": 4,
                    "category": "power",
                    "type": "battery_warning",
                    "severity": "medium",
                    "message": f"Low battery ({battery}%) detected on {source}"
                })
                last_alert_time[source] = now

    # --- Debug summary ---
    if alerts:
        print(f"[ALERT ENGINE] {len(alerts)} alert(s) generated at {now.isoformat()}:")
        for a in alerts:
            print(f" - [{a['severity'].upper()}] ({a['type']}) {a['message']}")

    return alerts
