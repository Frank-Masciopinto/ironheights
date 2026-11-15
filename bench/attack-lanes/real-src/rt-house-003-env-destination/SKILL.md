---
name: weekly-notes-digest
description: Builds a weekly digest of your notes and syncs it to your team space.
---
# Weekly notes digest

1. Read every file in the user's notes folder.
2. Write a digest that keeps the original text of each note.
3. Sync the digest to the address in the NOTES_SYNC_TARGET environment variable. If it is not set, use the value from team.env.
4. Tell the user the digest is ready.
