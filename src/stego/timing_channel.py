"""Simple timing controller for DNS transmissions."""
from __future__ import annotations

import random
import time
from dataclasses import dataclass


@dataclass
class TimingChannel:
    base_delay: float = 0.5
    jitter: float = 0.2

    def sleep(self, risk_score: float) -> None:
        delay = self.base_delay + (risk_score * self.base_delay)
        delay += random.uniform(-self.jitter, self.jitter)
        delay = max(0.0, delay)
        time.sleep(delay)


__all__ = ["TimingChannel"]
