"""Observation utilities for analysing DNS domain sequences."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, List


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    frequency = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in frequency.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class SequenceObservation:
    lengths: List[int]
    entropy: float
    average_length: float


def observe(domains: Iterable[str]) -> SequenceObservation:
    domains = list(domains)
    lengths = [len(d) for d in domains]
    total_sequence = "".join(domains)
    entropy = _shannon_entropy(total_sequence)
    average_length = sum(lengths) / len(lengths) if lengths else 0.0
    return SequenceObservation(lengths=lengths, entropy=entropy, average_length=average_length)


__all__ = ["SequenceObservation", "observe"]
