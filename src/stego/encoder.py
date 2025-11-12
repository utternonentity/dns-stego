"""Encoding utilities that transform binary payloads into DNS domains."""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from typing import Iterable, List

from ..utils.logger import get_logger

logger = get_logger(__name__)


def _sanitize_label(label: str) -> str:
    label = label.lower()
    return label.replace("_", "-")


def _split_chunks(data: bytes, chunk_size: int) -> List[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


@dataclass
class DomainEncoder:
    """Encode bytes into DNS queries."""

    base_domain: str
    chunk_size: int = 15
    encoding: str = "base32"

    def __post_init__(self) -> None:
        if self.encoding not in {"base32", "base64"}:
            raise ValueError("encoding must be 'base32' or 'base64'")
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

    def encode(self, data: bytes) -> List[str]:
        labels: List[str] = []
        for chunk in _split_chunks(data, self.chunk_size):
            encoded = self._encode_chunk(chunk)
            labels.append(encoded)
        domains = [f"{label}.{self.base_domain}" for label in labels]
        logger.debug("Encoded %d labels for domain %s", len(domains), self.base_domain)
        return domains

    def _encode_chunk(self, chunk: bytes) -> str:
        if self.encoding == "base32":
            encoded = base64.b32encode(chunk).decode("ascii")
        else:
            encoded = base64.urlsafe_b64encode(chunk).decode("ascii")
        encoded = encoded.strip("=")
        if len(encoded) > 63:
            raise ValueError("Encoded label exceeds maximum DNS label length")
        return _sanitize_label(encoded)


def encoded_length(data_length: int, chunk_size: int, encoding: str = "base32") -> int:
    """Return approximate encoded string length for sizing chunks."""
    ratio = 8 / 5 if encoding == "base32" else 4 / 3
    return math.ceil(chunk_size * ratio) * math.ceil(data_length / chunk_size)


def build_domains(
    data: bytes, base_domain: str, chunk_size: int = 15, encoding: str = "base32"
) -> List[str]:
    encoder = DomainEncoder(
        base_domain=base_domain, chunk_size=chunk_size, encoding=encoding
    )
    return encoder.encode(data)


def iter_domains(domains: Iterable[str]) -> Iterable[str]:
    for domain in domains:
        yield domain.strip()


__all__ = ["DomainEncoder", "build_domains", "iter_domains", "encoded_length"]
