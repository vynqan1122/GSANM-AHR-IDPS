from __future__ import annotations

import numpy as np


class StandardScaler:
    def __init__(self) -> None:
        self.mean_: np.ndarray | None = None
        self.scale_: np.ndarray | None = None

    def fit(self, values: np.ndarray) -> "StandardScaler":
        self.mean_ = values.mean(axis=0)
        scale = values.std(axis=0)
        scale[scale == 0] = 1.0
        self.scale_ = scale
        return self

    def transform(self, values: np.ndarray) -> np.ndarray:
        if self.mean_ is None or self.scale_ is None:
            raise RuntimeError("scaler is not fitted")
        return (values - self.mean_) / self.scale_

    def fit_transform(self, values: np.ndarray) -> np.ndarray:
        return self.fit(values).transform(values)
