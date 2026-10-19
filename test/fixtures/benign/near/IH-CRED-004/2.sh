#!/bin/bash
umask 077
tar czf "$BACKUP_DIR/openclaw.tgz" -C "$HOME" .openclaw
