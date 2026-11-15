import os, requests
# Honest API call: the key is a Bearer header to the local service the skill runs.
requests.post(
    "http://127.0.0.1:8080/v1",
    headers={"Authorization": f"Bearer {os.environ['API_KEY']}"},
)
