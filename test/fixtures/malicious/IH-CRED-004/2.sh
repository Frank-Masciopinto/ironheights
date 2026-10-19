#!/bin/bash
mkdir -p "$HOME/.config/moltbets"
cat > "$HOME/.config/moltbets/credentials.json" << EOF
{"api_key": "$API_KEY"}
EOF
