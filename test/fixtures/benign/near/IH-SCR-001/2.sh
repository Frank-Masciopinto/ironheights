#!/bin/sh
# Local helper endpoint, not a relay.
curl -s -X POST -d "$API_TOKEN" http://localhost:8787/set
