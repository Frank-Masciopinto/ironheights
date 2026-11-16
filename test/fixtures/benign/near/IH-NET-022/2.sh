#!/bin/sh
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user/repos
