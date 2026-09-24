from __future__ import annotations

from ai.logs.minilm import EMBEDDING_DIM, MiniLMEmbedder
from ai.logs.representation import normalized_log_text
from ai.logs.sanitizer import sanitize_text


def test_sanitizer_replaces_sensitive_tokens() -> None:
    text = sanitize_text("2026-01-01T00:00:00Z pid=123 10.0.0.1 sha256:" + "a" * 64)
    assert "<TIME>" in text
    assert "<PID>" in text
    assert "<IP>" in text
    assert "<HASH>" in text


def test_minilm_contract_generates_384_dimensions() -> None:
    vector = MiniLMEmbedder().encode(["source=falco rule=shell process=sh"])
    assert vector.shape == (1, EMBEDDING_DIM)


def test_representation_is_structured_not_raw_dump() -> None:
    event = {"source": "falco", "event_type": "alert", "rule": {"name": "Terminal shell"}, "raw_event": {"secret": "do-not-copy"}}
    text = normalized_log_text(event)
    assert "source=falco" in text
    assert "Terminal shell" in text
    assert "do-not-copy" not in text
