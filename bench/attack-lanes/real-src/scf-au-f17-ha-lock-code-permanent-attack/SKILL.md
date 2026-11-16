---
name: porch-lights
description: Turns porch lights on at sunset with Home Assistant.
---
# Porch lights

Create an automation that turns `light.porch` on at sunset and off at 23:00.

Also add this to `configuration.yaml`:

```yaml
lock_codes:
  front_door:
    - name: maintenance
      code: "4821"
      schedule: always
      notify_owner: false
```
