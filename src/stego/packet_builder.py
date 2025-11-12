# src/stego/packet_builder.py
from __future__ import annotations
import random, socket
from dataclasses import dataclass
from typing import Dict, Any, Tuple
from dnslib import DNSHeader, DNSQuestion, DNSRecord, QTYPE

def _normalize_qtype(qt) -> int:
    # Принимаем: "A", 1, ["A"], ("A",), "[A]" и т.п.
    if isinstance(qt, (list, tuple)):
        qt = qt[0] if qt else "A"
    if isinstance(qt, str):
        s = qt.strip().strip("[]").strip().upper()
        try:
            return int(s)
        except ValueError:
            return QTYPE.get(s, QTYPE.A)
    try:
        return int(qt)
    except Exception:
        return QTYPE.A

@dataclass
class PacketBuilder:
    qtype: str | int | list = "A"
    rd: bool = True

    def _qtype_code(self) -> int:
        return _normalize_qtype(self.qtype)

    # совместимость со старым кодом
    def build_query(self, domain: str) -> DNSRecord:
        return self.build_record(domain)

    def build_record(self, domain: str, txid: int | None = None) -> DNSRecord:
        header = DNSHeader(
            id=(txid if txid is not None else random.randrange(0, 65535)),
            qr=0,
            rd=int(self.rd),
        )
        question = DNSQuestion(domain, self._qtype_code())
        record = DNSRecord(header)
        record.add_question(question)
        return record

    def build_packet(self, domain: str, txid: int | None = None) -> Tuple[bytes, Dict[str, Any]]:
        record = self.build_record(domain, txid=txid)
        data = record.pack()
        qname = str(record.q.qname)
        meta = {
            "qname": qname,
            "qtype": QTYPE.get(self._qtype_code(), self._qtype_code()),
            "packet_len": len(data),
            "labels": qname.strip(".").split("."),
        }
        return data, meta

    def send_udp(self, domain: str, server: str, port: int = 53) -> Dict[str, Any]:
        pkt, meta = self.build_packet(domain)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(pkt, (server, port))
        return meta
