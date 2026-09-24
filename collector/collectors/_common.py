from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from ..base import canonical_json


def nested(document: Mapping[str, Any], *keys: str) -> Any:
    value: Any = document
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def stable_source_id(document: Mapping[str, Any], fields: Sequence[Any]) -> str:
    populated = [value for value in fields if value is not None and str(value) != ""]
    material = canonical_json(populated if populated else document)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()

