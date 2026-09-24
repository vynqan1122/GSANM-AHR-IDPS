from __future__ import annotations

from collections import Counter
from typing import Any


def attach_window_features(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_src = Counter(str(row.get("src_ip") or "") for row in rows)
    dst_by_src: dict[str, set[str]] = {}
    errors_by_src = Counter()
    for row in rows:
        src = str(row.get("src_ip") or "")
        dst_by_src.setdefault(src, set()).add(str(row.get("dst_ip") or ""))
        http = row.get("http") if isinstance(row.get("http"), dict) else {}
        if int(http.get("status") or 0) >= 400:
            errors_by_src[src] += 1
    enriched = []
    for row in rows:
        src = str(row.get("src_ip") or "")
        total = max(1, by_src[src])
        copy = dict(row)
        copy["connections_per_window"] = float(total)
        copy["unique_dst_per_window"] = float(len(dst_by_src.get(src, set())))
        copy["request_rate"] = float(total)
        copy["error_rate"] = float(errors_by_src[src] / total)
        enriched.append(copy)
    return enriched
