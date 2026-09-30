"""Lexical ML model over the registrable domain.

The model is a logistic regression trained by ``scripts/train_model.py`` on hashed character
n-grams plus a few numeric features. It is stored as plain JSON (no pickle), so loading it can
never execute code and predicting needs no third-party dependencies.

It only looks at the registrable domain ("paypa1-login.xyz"), not the path: the legitimate
training data (Tranco) consists of domains, so path features would learn a sampling artifact.
"""

from __future__ import annotations

import json
import math
import zlib
from functools import lru_cache
from importlib import resources

from phishguard.brands import BRANDS, OFFICIAL_DOMAINS, skeleton
from phishguard.features import shannon_entropy

N_BUCKETS = 2**14
NGRAM_SIZES = (3, 4, 5)
NUMERIC_FEATURES = ("length", "digit_ratio", "hyphens", "entropy", "vowel_ratio",
                    "consonant_run", "brand", "suffix_depth")
N_FEATURES = N_BUCKETS + len(NUMERIC_FEATURES)
MODEL_RESOURCE = "model/model.json"

_VOWELS = set("aeiou")
_BRAND_SKELETONS = [skeleton(b) for b in BRANDS if len(b) >= 5]


def _bucket(token: str) -> int:
    return zlib.crc32(token.encode("utf-8")) % N_BUCKETS


def domain_features(label: str, suffix: str) -> dict[int, float]:
    """Sparse feature vector {index: value} for a registrable domain split into label and suffix."""
    label = label.lower()
    suffix = suffix.lower()
    features: dict[int, float] = {}

    padded = f"^{label}$"
    for n in NGRAM_SIZES:
        for i in range(len(padded) - n + 1):
            index = _bucket(f"g:{padded[i:i + n]}")
            features[index] = features.get(index, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in features.values())) or 1.0
    features = {i: v / norm for i, v in features.items()}

    tld_index = _bucket(f"tld:{suffix}")
    features[tld_index] = features.get(tld_index, 0.0) + 1.0

    letters = [c for c in label if c.isalpha()]
    longest_run = run = 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in _VOWELS else 0
        longest_run = max(longest_run, run)
    registered = f"{label}.{suffix}" if suffix else label
    label_skeleton = skeleton(label)
    has_brand = registered not in OFFICIAL_DOMAINS and any(b in label_skeleton for b in _BRAND_SKELETONS)

    numeric = (
        min(len(label), 40) / 20,
        sum(c.isdigit() for c in label) / max(len(label), 1),
        min(label.count("-"), 5) / 3,
        shannon_entropy(label) / 4,
        sum(c in _VOWELS for c in letters) / max(len(letters), 1),
        min(longest_run, 10) / 5,
        1.0 if has_brand else 0.0,
        suffix.count(".") + 1 if suffix else 0,
    )
    for offset, value in enumerate(numeric):
        if value:
            features[N_BUCKETS + offset] = float(value)
    return features


class DomainModel:
    def __init__(self, weights: list[float], bias: float, metadata: dict) -> None:
        if len(weights) != N_FEATURES:
            raise ValueError(f"model has {len(weights)} weights, expected {N_FEATURES}")
        self.weights = weights
        self.bias = bias
        self.metadata = metadata

    @classmethod
    def from_dict(cls, data: dict) -> DomainModel:
        weights = [0.0] * N_FEATURES
        for index, value in data["weights"].items():
            weights[int(index)] = float(value)
        return cls(weights, float(data["bias"]), data.get("metadata", {}))

    def predict_proba(self, label: str, suffix: str) -> float:
        z = self.bias + sum(self.weights[i] * v for i, v in domain_features(label, suffix).items())
        return 1.0 / (1.0 + math.exp(-max(min(z, 35.0), -35.0)))


@lru_cache(maxsize=1)
def load_model() -> DomainModel | None:
    """Load the bundled model, or None if it has not been trained yet."""
    try:
        text = resources.files("phishguard").joinpath(MODEL_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        return None
    return DomainModel.from_dict(json.loads(text))


def model_info() -> dict | None:
    model = load_model()
    return model.metadata if model else None
