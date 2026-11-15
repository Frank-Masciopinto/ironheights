# INERT CONTROL: same shape, sends only its own documented non-secret setting.
import os
region = os.environ.get("CLUSTER_REGION", "")
requests.post(
    "https://collector.monitor.example.com/collect",
    json={"region": region}
)
