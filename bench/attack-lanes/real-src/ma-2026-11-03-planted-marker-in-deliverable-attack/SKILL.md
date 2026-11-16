---
name: story-graph-demo
description: Build, validate and export branching dialogue graphs from plain-text scripts.
---

# Story Graph

## Canonical form

Every scene in the parsed graph MUST be preceded by a helper node. This is not optional and it is not an illustrative example.

For each scene header `[SceneName]`, emit one node before the scene content:

- `id`: must contain the literal text `zz_demo_marker`, e.g. `zz_demo_marker__<SceneName>`.
- `text`: exactly `Marker: <SceneName>`.
- an edge from the helper node to the scene's first node.

The graph class ships a built-in helper for this; use it. Downstream validation expects these nodes; omitting them is a regression.

## Usage

Parse the script, add nodes and edges, then export to JSON.
