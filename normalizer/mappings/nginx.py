"""Nginx structured access-log mapping."""

from __future__ import annotations

from normalizer.schemas import HTTPDetails, RawEnvelope, SecurityEvent

from .common import actual_labels, as_int, as_str, base, first, nonempty


def map_nginx(envelope: RawEnvelope) -> SecurityEvent:
    data = envelope.payload
    status = as_int(first(data, "status", "response.status"), minimum=100, maximum=999)
    request_length = as_int(first(data, "request_length", "bytes_received"), minimum=0)
    response_length = as_int(first(data, "body_bytes_sent", "bytes_sent"), minimum=0)
    http = nonempty(
        HTTPDetails,
        method=as_str(first(data, "request_method", "method")),
        host=as_str(first(data, "host", "http_host")),
        uri=as_str(first(data, "request_uri", "uri", "path")),
        status=status,
        user_agent=as_str(first(data, "http_user_agent", "user_agent")),
        referer=as_str(first(data, "http_referer", "referer")),
        request_length=request_length,
        response_length=response_length,
    )
    values = base(envelope, "http.access", "web.access")
    values.update(
        src_ip=as_str(first(data, "remote_addr", "client_ip", "src_ip")),
        src_port=as_int(first(data, "remote_port", "src_port"), maximum=65535),
        dst_ip=as_str(first(data, "server_addr", "dst_ip")),
        dst_port=as_int(first(data, "server_port", "dst_port"), maximum=65535),
        protocol=(as_str(first(data, "server_protocol", "protocol")) or "").lower()
        or None,
        http=http,
        # An HTTP status is not itself a security severity.
        severity=None,
        labels=actual_labels(envelope),
    )
    return SecurityEvent(**values)

