"""High level interface for sending and receiving messages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..stego import DomainDecoder, DomainEncoder
from ..transport.dns_sender import DNSSender
from ..utils.crypto import AESCipher
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TunnelClient:
    base_domain: str
    password: str
    chunk_size: int = 15
    encoding: str = "base32"
    dns_server: str = "8.8.8.8"
    dns_port: int = 53

    def _encrypt(self, message: bytes) -> bytes:
        cipher = AESCipher(self.password)
        return cipher.encrypt(message)

    def _decrypt(self, blob: bytes) -> bytes:
        cipher = AESCipher(self.password)
        return cipher.decrypt(blob)

    def prepare_domains(self, message: bytes) -> list[str]:
        encrypted = self._encrypt(message)
        encoder = DomainEncoder(self.base_domain, self.chunk_size, self.encoding)
        return encoder.encode(encrypted)

    def send(self, message: bytes) -> None:
        domains = self.prepare_domains(message)
        sender = DNSSender(server=self.dns_server, port=self.dns_port)
        sender.send_domains(domains)

    def decode(self, domains: Iterable[str]) -> bytes:
        decoder = DomainDecoder(self.base_domain, self.encoding)
        encrypted = decoder.decode(domains)
        return self._decrypt(encrypted)


__all__ = ["TunnelClient"]
