from __future__ import annotations

from typing import Any


def render(pattern: dict[str, Any]) -> str:
    container = str(pattern.get("container_role") or "container")
    process = str(pattern.get("process_family") or "shell")
    return f"""- rule: AHR Generated Runtime Behavior
  desc: Candidate-only repeated runtime behavior in {container}
  condition: spawned_process and container.name != "" and proc.name contains "{process[:32]}"
  output: AHR generated runtime candidate (container=%container.name proc=%proc.name)
  priority: WARNING
  tags: [ahr, generated, candidate]
"""

