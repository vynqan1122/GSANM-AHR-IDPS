"""Wazuh alerts.json mapping."""

from __future__ import annotations

from normalizer.schemas import (
    ContainerDetails,
    FileDetails,
    NetworkDetails,
    ProcessDetails,
    RawEnvelope,
    RuleDetails,
    SecurityEvent,
    UserDetails,
)

from .common import actual_labels, as_int, as_str, base, first, nonempty


def _severity(level: int | None) -> int | None:
    if level is None:
        return None
    # Wazuh rule levels are 0..16. Preserve ordering on the canonical 0..10 scale.
    return min(10, max(0, round(level * 10 / 16)))


def map_wazuh(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    rule_data = data.get("rule") if isinstance(data.get("rule"), dict) else {}
    event_data = data.get("data") if isinstance(data.get("data"), dict) else {}
    docker_data = (
        event_data.get("docker") if isinstance(event_data.get("docker"), dict) else {}
    )
    level = as_int(first(rule_data, "level"), maximum=16)
    severity = _severity(level)
    groups = rule_data.get("groups")
    tags = [str(item) for item in groups] if isinstance(groups, list) else []
    category = tags[0] if tags else as_str(first(data, "decoder.name")) or "host.alert"

    container_labels = first(docker_data, "Actor.Attributes.labels")
    if not isinstance(container_labels, dict):
        container_labels = {}
    container = nonempty(
        ContainerDetails,
        id=as_str(
            first(
                docker_data,
                "id",
                "Actor.ID",
                "actor.id",
            )
        ),
        name=as_str(
            first(
                docker_data,
                "name",
                "Actor.Attributes.name",
                "actor.attributes.name",
                "container.name",
            )
        ),
        image=as_str(
            first(
                docker_data,
                "from",
                "Actor.Attributes.image",
                "actor.attributes.image",
            )
        ),
        runtime="docker" if docker_data else None,
        labels={str(k): str(v) for k, v in container_labels.items()},
    )
    process = nonempty(
        ProcessDetails,
        pid=as_int(first(event_data, "pid", "process.pid")),
        ppid=as_int(first(event_data, "ppid", "process.ppid")),
        name=as_str(first(event_data, "process.name", "program_name")),
        parent_name=as_str(first(event_data, "process.parent_name")),
        exe=as_str(first(event_data, "process.executable", "exe")),
        cmdline=as_str(first(event_data, "process.command_line", "command")),
    )
    user = nonempty(
        UserDetails,
        name=as_str(first(event_data, "srcuser", "dstuser", "user")),
        uid=as_str(first(event_data, "uid")),
    )
    file_details = nonempty(
        FileDetails,
        path=as_str(first(event_data, "path", "file", "syscheck.path")),
        name=as_str(first(event_data, "filename")),
        operation=as_str(first(event_data, "action", "syscheck.event")),
        hash_sha256=as_str(first(event_data, "sha256_after", "syscheck.sha256_after")),
    )
    network = nonempty(
        NetworkDetails,
        interface=as_str(first(event_data, "in_iface")),
        flow_id=as_str(first(event_data, "flow_id")),
    )
    rule = RuleDetails(
        engine="wazuh",
        rule_id=as_str(first(rule_data, "id")),
        name=as_str(first(rule_data, "description")),
        category=category,
        severity=severity,
        tags=tags,
    )
    values = base(envelope, "alert", category)
    values.update(
        src_ip=as_str(first(data, "srcip", "data.srcip", "data.src_ip")),
        src_port=as_int(
            first(data, "srcport", "data.srcport", "data.src_port"), maximum=65535
        ),
        dst_ip=as_str(first(data, "dstip", "data.dstip", "data.dest_ip")),
        dst_port=as_int(
            first(data, "dstport", "data.dstport", "data.dest_port"), maximum=65535
        ),
        protocol=(as_str(first(data, "protocol", "data.protocol", "data.proto")) or "").lower()
        or None,
        container=container,
        process=process,
        user=user,
        file=file_details,
        network=network,
        rule=rule,
        severity=severity,
        labels=actual_labels(envelope),
    )
    return SecurityEvent(**values)

