"""Simple DNS listener to collect queries for decoding."""

from __future__ import annotations

import queue
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from dnslib import QTYPE, RR, A, DNSHeader, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from ..utils.logger import get_logger

logger = get_logger(__name__)


class _QueueResolver(BaseResolver):
    def __init__(self, domain_queue: "queue.Queue[str]", response_ip: str) -> None:
        self.domain_queue = domain_queue
        self.response_ip = response_ip

    def resolve(self, request: DNSRecord, handler):  # type: ignore[override]
        qname = request.q.qname
        self.domain_queue.put(str(qname).rstrip("."))
        logger.debug("Captured query %s", qname)
        reply = request.reply()
        reply.header = DNSHeader(id=request.header.id, qr=1, aa=1, ra=1)
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.response_ip), ttl=60))
        return reply


@dataclass
class DNSListener:
    ip: str = "0.0.0.0"
    port: int = 5353
    response_ip: str = "127.0.0.1"
    _queue: "queue.Queue[str]" = field(default_factory=queue.Queue, init=False)
    _server: Optional[DNSServer] = field(default=None, init=False)

    def start(self) -> None:
        resolver = _QueueResolver(self._queue, self.response_ip)
        self._server = DNSServer(resolver, port=self.port, address=self.ip, tcp=False)
        self._server.start_thread()
        logger.info("DNS listener started on %s:%d", self.ip, self.port)

    def stop(self) -> None:
        if self._server:
            self._server.stop()
        logger.info("DNS listener stopped")

    def collect(self, limit: Optional[int] = None) -> List[str]:
        domains: List[str] = []
        while limit is None or len(domains) < limit:
            try:
                domain = self._queue.get(timeout=1)
                domains.append(domain)
            except queue.Empty:
                break
        return domains

    def __iter__(self) -> Iterable[str]:
        while True:
            domain = self._queue.get()
            yield domain


__all__ = ["DNSListener"]
