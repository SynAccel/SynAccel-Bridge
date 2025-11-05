from datetime import datetime, timezone, timedelta

# A dictionary to remember when each source last triggered an alert
last_alert_time = {}

def correlate_events(events):
    """
    Analyze recent events for abnormal patterns.
    Returns a list of generated alerts.
    """
    alerts = []
    now = datetime.now(timezone.utc)

    # --- Parameters ---
    INTRUSION_THRESHOLD = 3          # how many intrusions before alert
    COOLDOWN_PERIOD = timedelta(seconds=60)  # wait 60s before re-alerting same source
    WINDOW = timedelta(seconds=30)   # only look at events within last 30 s

    # --- Filter only recent events ---
    recent_window = [
        e for e in events
        if now - datetime.fromisoformat(e["timestamp"]) <= WINDOW
    ]

    # --- Example 1: repeated intrusions from same source ---
    intrusion_counts = {}
    for e in recent_window:
        if e["type"] == "intrusion":
            intrusion_counts[e["source"]] = intrusion_counts.get(e["source"], 0) + 1

    for src, count in intrusion_counts.items():
        if count >= INTRUSION_THRESHOLD:
            # cooldown check
            if src not in last_alert_time or now - last_alert_time[src] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": src,
                    "type": "intrusion_spike",
                    "severity": "high",
                    "message": f"{count} intrusion events from {src} within short timeframe"
                })
                last_alert_time[src] = now  # remember time of alert

    # --- Example 2: motion followed by access_denied from same source ---
    for i in range(len(recent_window) - 1):
        if (
            recent_window[i]["type"] == "motion"
            and recent_window[i + 1]["type"] == "access_denied"
            and recent_window[i]["source"] == recent_window[i + 1]["source"]
        ):
            src = recent_window[i]["source"]
            if src not in last_alert_time or now - last_alert_time[src] > COOLDOWN_PERIOD:
                alerts.append({
                    "timestamp": now.isoformat(),
                    "source": src,
                    "type": "sequence_alert",
                    "severity": "medium",
                    "message": f"Motion followed by access_denied on {src}"
                })
                last_alert_time[src] = now

    return alerts
