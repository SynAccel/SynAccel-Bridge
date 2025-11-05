# SynAccel-Bridge

SynAccel-Bridge is the starting point for building a **cyber-physical event bridge** — a system that connects digital security platforms (like cloud or SOC systems) with physical and automated systems (like sensors, access controllers, or robotics).

The main goal is to learn and design how **real-time data** from both cyber and physical sources can be received, validated, and processed securely.  
It acts as the foundation for future research in **automation, robotics, and adaptive defense systems** under SynAccel Cyber.

### Current Focus
- Building a small FastAPI backend that receives and validates events
- Understanding how APIs move and secure data between systems
- Creating the first version of a “bridge” that could later connect IoT, security sensors, and automation logic

### Example Event
```json
{
  "source": "door_sensor_A1",
  "type": "motion",
  "details": {
    "zone": "server_room",
    "confidence": 0.95
  }
}
```

### Authentication and Logging

```
Device or Client  --->  SynAccel-Bridge API  --->  logs/events_log.jsonl
                       (auth + validation)       (timestamped entries)
```

### Experiment with event correlation and adaptive responses

| Component              | Description                                                   | Status |
| ---------------------- | ------------------------------------------------------------- | ------ |
| **Event Intake (API)** | `/api/event` endpoint using FastAPI, with Pydantic validation | Done |
| **Authentication**     | Secure API-key system via `.env` + header check               | Done |
| **Logging**            | Automatic logging to `events_log.jsonl`                       | Done |
| **Correlation Engine** | Detects repeated intrusions + motion/access_denied sequence   | Done |
| **Adaptive Responses** | Prints “isolation” or “diagnostic” actions                    | Done |
| **Cooldown Logic**     | Prevents spammy re-alerts, makes system time-aware            | Done |
| **Simulated Feed**     | `sensor_simulator.py` continuously generates events           | Done |


### Next Steps

- Expand to IoT or robotic telemetry integration
