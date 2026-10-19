#!/bin/bash
set -e
STAMP=$(date +%F)
tar czf "$BACKUP_DIR/openclaw-$STAMP.tgz" -C "$HOME" .openclaw
tar czf "/tmp/backup.tgz" ~/.openclaw
