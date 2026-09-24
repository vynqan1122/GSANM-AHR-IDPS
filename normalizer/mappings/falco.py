"""Falco JSON output mapping."""

from __future__ import annotations

from pathlib import PurePosixPath

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


FALCO_SEVERITY = {
    "emergency": 10,
    "alert": 10,
    "critical": 9,
    "error": 8,
    "warning": 6,
    "notice": 5,
    "informational": 3,
    "info": 3,
    "debug": 1,
}


def _tags(data: dict) -> list[str]:
    value = data.get("tags")
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def map_falco(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    fields = data.get("output_fields")
    fields = fields if isinstance(fields, dict) else {}
    priority = (as_str(first(data, "priority")) or "").lower()
    severity = FALCO_SEVERITY.get(priority)
    tags = _tags(data)
    category = tags[0] if tags else "runtime.alert"
    file_path = as_str(first(fields, "fd.name", "fs.path.name", "fd.directory"))
    file_name = PurePosixPath(file_path).name if file_path else None

    container_labels = first(fields, "container.labels")
    if not isinstance(container_labels, dict):
        container_labels = {}
    container = nonempty(
        ContainerDetails,
        id=as_str(first(fields, "container.id", "container.full_id")),
        name=as_str(first(fields, "container.name")),
        image=as_str(
            first(fields, "container.image.repository", "container.image")
        ),
        runtime=as_str(first(fields, "container.runtime")) or (
            "container" if first(fields, "container.id") else None
        ),
        labels={str(k): str(v) for k, v in container_labels.items()},
    )
    process = nonempty(
        ProcessDetails,
        pid=as_int(first(fields, "proc.pid")),
        ppid=as_int(first(fields, "proc.ppid")),
        name=as_str(first(fields, "proc.name")),
        parent_name=as_str(first(fields, "proc.pname")),
        exe=as_str(first(fields, "proc.exepath", "proc.exe")),
        cmdline=as_str(first(fields, "proc.cmdline")),
    )
    user = nonempty(
        UserDetails,
        name=as_str(first(fields, "user.name")),
        uid=as_str(first(fields, "user.uid")),
        effective_name=as_str(first(fields, "user.loginname")),
        effective_uid=as_str(first(fields, "user.loginuid")),
    )
    file_details = nonempty(
        FileDetails,
        path=file_path,
        name=file_name,
        directory=as_str(first(fields, "fd.directory")),
        operation=as_str(first(fields, "evt.type")),
    )
    network = nonempty(
        NetworkDetails,
        direction=as_str(first(fields, "fd.typechar")),
    )
    rule_name = as_str(first(data, "rule"))
    rule = nonempty(
        RuleDetails,
        engine="falco",
        rule_id=rule_name,
        name=rule_name,
        category=category,
        severity=severity,
        tags=tags,
    )
    values = base(envelope, "alert", category)
    # evt.time is the event timestamp while top-level time is Falco output time.
    if first(fields, "evt.time") is not None:
        from .common import timestamp

        values["timestamp"] = timestamp(first(fields, "evt.time"), envelope.observed_at)
    values.update(
        src_ip=as_str(first(fields, "fd.cip", "fd.sip")),
        src_port=as_int(first(fields, "fd.cport", "fd.sport"), maximum=65535),
        dst_ip=as_str(first(fields, "fd.sip", "fd.rip")),
        dst_port=as_int(first(fields, "fd.sport", "fd.rport"), maximum=65535),
        protocol=(as_str(first(fields, "fd.l4proto")) or "").lower() or None,
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

