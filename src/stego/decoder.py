"""Decode domain sequences back into the original payload."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Iterable

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DomainDecoder:
    base_domain: str
    encoding: str = "base32"

    def __post_init__(self) -> None:
        if self.encoding not in {"base32", "base64"}:
            raise ValueError("encoding must be 'base32' or 'base64'")

    def decode(self, domains: Iterable[str]) -> bytes:
        payload_parts = []
        suffix = f".{self.base_domain}".lower()
        for domain in domains:
            domain = domain.strip().lower()
            if not domain.endswith(suffix):
                logger.debug("Skipping domain %s - wrong suffix", domain)
                continue
            label = domain[: -len(suffix)]
            label = label.replace("-", "")
            if self.encoding == "base32":
                padded = label.upper()
                padding = (-len(padded)) % 8
                padded += "=" * padding
                decoded = base64.b32decode(padded)
            else:
                padded = label
                padding = (-len(padded)) % 4
                padded += "=" * padding
                decoded = base64.urlsafe_b64decode(padded)
            payload_parts.append(decoded)
        return b"".join(payload_parts)


def decode_domains(
    domains: Iterable[str], base_domain: str, encoding: str = "base32"
) -> bytes:
    decoder = DomainDecoder(base_domain=base_domain, encoding=encoding)
    return decoder.decode(domains)


__all__ = ["DomainDecoder", "decode_domains"]
