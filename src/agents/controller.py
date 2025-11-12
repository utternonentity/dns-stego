"""Risk controller that adapts the transmission strategy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .observer import observe


@dataclass
class RiskController:
    max_length: int = 50
    entropy_threshold: float = 4.0

    def assess_risk(self, domains: Iterable[str]) -> float:
        observation = observe(domains)
        if not observation.lengths:
            return 0.0
        length_score = max((max(observation.lengths) - self.max_length) / self.max_length, 0)
        entropy_score = max((observation.entropy - self.entropy_threshold) / self.entropy_threshold, 0)
        # Combine scores and normalise
        score = min(1.0, (length_score + entropy_score) / 2)
        return score


__all__ = ["RiskController"]
