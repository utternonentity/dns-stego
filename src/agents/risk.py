# src/agents/risk.py
from collections import Counter
from math import log2


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((freq / n) * log2(freq / n) for freq in c.values())


class RiskController:
    """
    Минимальный контроллер «риска»: оценивает энтропию доменных меток и их количество.
    """

    def __init__(self, max_entropy_threshold: float = 4.0, max_label_count: int = 25):
        self.max_entropy_threshold = max_entropy_threshold
        self.max_label_count = max_label_count

    def assess(self, labels: list[str]) -> dict:
        # объединяем все метки в одну строку для грубой оценки энтропии
        joined = ".".join(labels)
        ent = _shannon_entropy(joined.replace(".", ""))
        return {
            "label_count": len(labels),
            "entropy": ent,
            "ok": (
                ent <= self.max_entropy_threshold
                and len(labels) <= self.max_label_count
            ),
        }
