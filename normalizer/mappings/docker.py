"""Docker Engine event mapping."""

from __future__ import annotations

from normalizer.schemas import ContainerDetails, RawEnvelope, SecurityEvent

from .common import actual_labels, as_str, base, first, nonempty, timestamp


def map_docker(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    actor = data.get("Actor") if isinstance(data.get("Actor"), dict) else {}
    attributes = (
        actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
    )
    action = as_str(first(data, "Action", "status")) or "event"
    object_type = as_str(first(data, "Type", "type")) or "docker"
    container = None
    if object_type.lower() == "container":
        labels = {
            str(key)[len("label.") :]: str(value)
            for key, value in attributes.items()
            if str(key).startswith("label.")
        }
        container = nonempty(
            ContainerDetails,
            id=as_str(first(actor, "ID")) or as_str(first(data, "id")),
            name=as_str(first(attributes, "name")),
            image=as_str(first(attributes, "image")) or as_str(first(data, "from")),
            runtime="docker",
            labels=labels,
        )
    values = base(envelope, f"{object_type.lower()}.{action.lower()}", "runtime.lifecycle")
    if first(data, "timeNano", "time") is not None:
        values["timestamp"] = timestamp(
            first(data, "timeNano", "time"), envelope.observed_at
        )
    values.update(
        container=container,
        severity=None,
        labels=actual_labels(envelope),
    )
    return SecurityEvent(**values)

