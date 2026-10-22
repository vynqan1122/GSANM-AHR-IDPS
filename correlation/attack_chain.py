from __future__ import annotations

from typing import Any
from feature_engine.event_contract import decode_event
from .web_graph import source_address


def _node(nodes: dict[str, dict[str, Any]], node_id: str, label: str, kind: str) -> str:
    nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind})
    return node_id


def _edge(edges: list[dict[str, Any]], src: str, dst: str, relationship: str, timestamp: Any, event_id: str) -> None:
    if src and dst and src != dst:
        edges.append(
            {
                "source": src,
                "target": dst,
                "relationship": relationship,
                "timestamp": str(timestamp),
                "event_id": event_id,
            }
        )


def build_attack_chain(events: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for event in sorted(events, key=lambda item: str(item.get("timestamp") or "")):
        event = decode_event(event)
        event_id = str(event["event_id"])
        timestamp = event.get("timestamp")
        ip, origin = source_address(event)
        src = _node(nodes, f"ip:{ip}" if ip else f"unattributed:{event_id}",
                    ip or "Nguồn chưa ghi nhận IP", "ip" if ip else "unattributed")
        nodes[src]['details'] = {'address_source': origin}
        request_label = str((event.get("http") or {}).get("uri") or (event.get("http") or {}).get("url") or event.get("event_type"))
        request = _node(nodes, f"request:{event_id}", request_label, "request")
        target_label = str((event.get("container") or {}).get("name") or event.get("dst_ip") or "target")
        target = _node(nodes, f"target:{target_label}", target_label, "target")
        _edge(edges, src, request, "sent", timestamp, event_id)
        _edge(edges, request, target, "reached", timestamp, event_id)

        process = event.get("process") if isinstance(event.get("process"), dict) else {}
        if process:
            proc_label = str(process.get("name") or process.get("command_line") or "process")
            proc = _node(nodes, f"process:{proc_label}", proc_label, "process")
            _edge(edges, target, proc, "spawned", timestamp, event_id)

        file_details = event.get("file_details") if isinstance(event.get("file_details"), dict) else {}
        if file_details:
            file_label = str(file_details.get("path") or file_details.get("name") or "file")
            file_node = _node(nodes, f"file:{file_label}", file_label, "file")
            _edge(edges, target, file_node, "touched", timestamp, event_id)

        network = event.get("network") if isinstance(event.get("network"), dict) else {}
        outbound = network.get("outbound_ip") or network.get("dest_ip")
        if outbound:
            out = _node(nodes, f"ip:{outbound}", str(outbound), "ip")
            _edge(edges, target, out, "outbound", timestamp, event_id)

    return {"nodes": list(nodes.values()), "edges": edges}


def build_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for event in sorted(events, key=lambda item: str(item.get("timestamp") or "")):
        ai = event.get("ai") if isinstance(event.get("ai"), dict) else {}
        rows.append(
            {
                "timestamp": str(event.get("timestamp")),
                "event_id": event.get("event_id"),
                "source": event.get("source"),
                "event_type": event.get("event_type"),
                "severity": event.get("severity"),
                "fusion_score": ai.get("fusion_score"),
                "risk_level": ai.get("risk_level"),
            }
        )
    return rows

