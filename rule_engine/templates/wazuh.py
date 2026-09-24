from __future__ import annotations

from typing import Any


def render(pattern: dict[str, Any], rule_id: int) -> str:
    event_type = str(pattern.get("event_type") or "alert")
    return f"""<group name="ahr,generated,candidate">
  <rule id="{rule_id}" level="7">
    <field name="event_type">{event_type}</field>
    <description>AHR generated repeated host/security-log behavior</description>
  </rule>
</group>
"""

