from __future__ import annotations

import hashlib

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer

EMBEDDING_DIM = 384


class MiniLMEmbedder:
    """384-dimensional embedding contract with a deterministic local backend.

    The interface mirrors all-MiniLM-L6-v2 output size and caches repeated
    sanitized templates. The local backend keeps the lab runnable without a
    heavyweight Torch download; callers can swap this class for a
    sentence-transformers implementation without changing model consumers.
    """

    def __init__(self) -> None:
        self.vectorizer = HashingVectorizer(
            n_features=EMBEDDING_DIM,
            alternate_sign=False,
            norm="l2",
            lowercase=True,
        )
        self.cache: dict[str, np.ndarray] = {}

    @staticmethod
    def template_key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def encode_one(self, text: str) -> np.ndarray:
        key = self.template_key(text)
        if key not in self.cache:
            self.cache[key] = self.vectorizer.transform([text]).toarray()[0].astype(np.float32)
        return self.cache[key]

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.vstack([self.encode_one(text) for text in texts]).astype(np.float32)
