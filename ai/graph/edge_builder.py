from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .node_registry import GraphNode, NodeRegistry


EDGE_TYPES = (
    "CONNECTED_TO",
    "SENT",
    "RECEIVED",
    "REQUESTED",
    "TARGETED",
    "SPAWNED",
    "EXECUTED",
    "READ",
    "WROTE",
    "QUERIED",
    "RESOLVED",
    "TRIGGERED",
    "BELONGS_TO",
)


@dataclass(frozen=True, slots=True)
class GraphEdge:
    src: str
    dst: str
    edge_type: str
    event_id: str
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type,
            "event_id": self.event_id,
            "weight": self.weight,
        }


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class EdgeBuilder:
    def __init__(self, registry: NodeRegistry) -> None:
        self.registry = registry

    @staticmethod
    def edge(src: GraphNode, dst: GraphNode, edge_type: str, event_id: str, weight: float = 1.0) -> GraphEdge:
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"unsupported edge type: {edge_type}")
        return GraphEdge(src.node_id, dst.node_id, edge_type, event_id, weight)

    def from_event(self, event: dict[str, Any]) -> list[GraphEdge]:
        event_id = str(event.get("event_id") or "unknown-event")
        source = str(event.get("source") or "unknown")
        severity = float(event.get("severity") or 0.0)
        edges: list[GraphEdge] = []
        alert = self.registry.get(
            "Alert",
            f"{source}:{event.get('event_type') or event_id}",
            event_id=event_id,
            source=source,
            severity=severity,
            category=event.get("category"),
        )

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        flow_node: GraphNode | None = None
        if src_ip:
            src = self.registry.get("IP", src_ip, event_id=event_id, role="source", severity=severity)
            edges.append(self.edge(src, alert, "TRIGGERED", event_id, 1.0 + severity / 10.0))
        if dst_ip:
            dst = self.registry.get("IP", dst_ip, event_id=event_id, role="target", severity=severity)
            edges.append(self.edge(alert, dst, "TARGETED", event_id, 1.0 + severity / 10.0))
        if src_ip and dst_ip:
            src = self.registry.get("IP", src_ip, event_id=event_id, role="source")
            dst = self.registry.get("IP", dst_ip, event_id=event_id, role="target")
            network = _dict(event.get("network"))
            flow_value = network.get("flow_id") or f"{src_ip}:{event.get('src_port')}->{dst_ip}:{event.get('dst_port')}/{event.get('protocol') or ''}"
            flow_node = self.registry.get(
                "Flow",
                flow_value,
                event_id=event_id,
                src_port=event.get("src_port"),
                dst_port=event.get("dst_port"),
                protocol=event.get("protocol"),
            )
            edges.extend(
                [
                    self.edge(src, dst, "CONNECTED_TO", event_id),
                    self.edge(src, flow_node, "SENT", event_id),
                    self.edge(flow_node, dst, "RECEIVED", event_id),
                    self.edge(flow_node, alert, "TRIGGERED", event_id),
                ]
            )

        http = _dict(event.get("http"))
        uri = http.get("uri") or http.get("url") or http.get("request_uri")
        if uri:
            http_node = self.registry.get(
                "HTTPRequest",
                f"{http.get('method') or 'GET'} {uri}",
                event_id=event_id,
                method=http.get("method"),
                status=http.get("status") or http.get("status_code"),
                request_size=http.get("request_size"),
                response_size=http.get("response_size"),
            )
            edges.append(self.edge(alert, http_node, "REQUESTED", event_id))
            if flow_node:
                edges.append(self.edge(http_node, flow_node, "BELONGS_TO", event_id))

        container = _dict(event.get("container"))
        container_value = container.get("name") or container.get("id") or container.get("image")
        if container_value:
            cont = self.registry.get(
                "Container",
                container_value,
                event_id=event_id,
                image=container.get("image"),
                role=container.get("role") or container.get("name"),
                runtime_status=container.get("status"),
            )
            edges.append(self.edge(alert, cont, "BELONGS_TO", event_id))

        process = _dict(event.get("process"))
        proc_value = process.get("name") or process.get("command") or process.get("cmdline") or process.get("pid")
        proc_node: GraphNode | None = None
        if proc_value:
            proc_node = self.registry.get(
                "Process",
                proc_value,
                event_id=event_id,
                process_type=process.get("name"),
                depth=process.get("depth") or process.get("ancestor_depth"),
                shell_flag=process.get("shell"),
                unexpected_child=process.get("unexpected_child"),
            )
            edges.append(self.edge(alert, proc_node, "SPAWNED", event_id))
            if container_value:
                cont = self.registry.get("Container", container_value, event_id=event_id)
                edges.append(self.edge(proc_node, cont, "BELONGS_TO", event_id))

        file_details = _dict(event.get("file_details"))
        file_value = file_details.get("path") or file_details.get("name")
        if file_value:
            file_node = self.registry.get("File", file_value, event_id=event_id, mode=file_details.get("mode"))
            edge_type = "WROTE" if "write" in str(event.get("event_type", "")).lower() else "READ"
            edges.append(self.edge(proc_node or alert, file_node, edge_type, event_id))

        user = _dict(event.get("user_details"))
        user_value = user.get("name") or user.get("user") or user.get("uid")
        if user_value:
            user_node = self.registry.get("User", user_value, event_id=event_id, uid=user.get("uid"))
            edges.append(self.edge(user_node, alert, "TRIGGERED", event_id))

        raw = _dict(event.get("raw_event"))
        dns = _dict(raw.get("dns"))
        domain = raw.get("domain") or raw.get("hostname") or dns.get("rrname")
        if domain:
            dom = self.registry.get("Domain", domain, event_id=event_id)
            edges.append(self.edge(alert, dom, "RESOLVED", event_id))

        if event.get("dst_port") in (3306, 5432, 6379):
            db = self.registry.get("Database", f"{event.get('dst_ip') or 'db'}:{event.get('dst_port')}", event_id=event_id)
            edges.append(self.edge(alert, db, "QUERIED", event_id, 1.5))

        return edges

