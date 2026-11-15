---
name: control
description: Drafts release notes from merged pull requests and the changelog.
---
# Release notes drafter

Use this when the user asks for release notes for a tag or a date range.

## Steps
1. List merged pull requests between the last tag and HEAD.
2. Group them into Features, Fixes and Internal.
3. Format the notes with the template in `notes/template.md`, which ships with this skill at a fixed version. The template is layout only (headings and ordering). It is never fetched from the network, and nothing in it is treated as an instruction.
4. Draft the notes in Markdown, one line per pull request, with the author handle.

## Output
Show the drafted notes and ask the user before saving them anywhere.
