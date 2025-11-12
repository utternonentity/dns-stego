"""Command line interface for the dnsstego toolkit."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional

from src.agents import RiskController
from src.stego import DomainDecoder
from src.transport import DNSListener, TunnelClient
from src.transport.dns_sender import DNSSender
from src.utils import AESCipher, get_logger

logger = get_logger("dnsstego")


def _read_bytes(path: Optional[Path], text: Optional[str]) -> bytes:
    if path is not None:
        return path.read_bytes()
    if text is not None:
        return text.encode("utf-8")
    data = sys.stdin.buffer.read()
    if not data:
        raise ValueError("No data provided")
    return data


def _write_output(data: bytes, output: Optional[Path]) -> None:
    if output is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.write(b"\n")
        return
    output.write_bytes(data)
    logger.info("Wrote %d bytes to %s", len(data), output)


def cmd_send(args: argparse.Namespace) -> None:
    message = _read_bytes(args.file, args.message)
    client = TunnelClient(
        base_domain=args.base_domain,
        password=args.password,
        chunk_size=args.chunk_size,
        encoding=args.encoding,
        dns_server=args.server,
        dns_port=args.port,
    )
    domains = client.prepare_domains(message)
    risk = RiskController().assess_risk(domains[: args.risk_window])
    logger.info("Initial risk score %.2f", risk)
    if args.dry_run:
        for domain in domains:
            print(domain)
        return
    sender = DNSSender(server=args.server, port=args.port)
    sender.send_domains(domains, risk_window=args.risk_window)


def _collect_domains(listener: DNSListener, limit: Optional[int], timeout: Optional[float]) -> List[str]:
    collected: List[str] = []
    start = time.time()
    while True:
        remaining = None if limit is None else max(limit - len(collected), 0)
        if limit is not None and remaining <= 0:
            break
        chunk = listener.collect(limit=remaining if remaining else None)
        if chunk:
            collected.extend(chunk)
        if timeout is not None and (time.time() - start) >= timeout:
            break
        if not chunk:
            time.sleep(0.2)
    return collected


def cmd_receive(args: argparse.Namespace) -> None:
    decoder = DomainDecoder(args.base_domain, args.encoding)
    cipher = AESCipher(args.password)
    if args.domains_file:
        domains = [line.strip() for line in Path(args.domains_file).read_text().splitlines() if line.strip()]
    else:
        listener = DNSListener(port=args.port, response_ip=args.response_ip)
        listener.start()
        try:
            domains = _collect_domains(listener, args.limit, args.timeout)
        finally:
            listener.stop()
    if not domains:
        logger.warning("No domains captured")
        return
    encrypted = decoder.decode(domains)
    if not encrypted:
        logger.warning("No payload recovered")
        return
    message = cipher.decrypt(encrypted)
    _write_output(message, args.output)


def cmd_tunnel(args: argparse.Namespace) -> None:
    message = _read_bytes(args.file, args.message)
    client = TunnelClient(
        base_domain=args.base_domain,
        password=args.password,
        chunk_size=args.chunk_size,
        encoding=args.encoding,
        dns_server=args.server,
        dns_port=args.port,
    )
    domains = client.prepare_domains(message)
    logger.info("Prepared %d domains", len(domains))
    if args.print_only:
        for domain in domains:
            print(domain)
        return
    sender = DNSSender(server=args.server, port=args.port)
    sender.send_domains(domains, risk_window=args.risk_window)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dnsstego command line interface")
    sub = parser.add_subparsers(dest="command", required=True)

    send_parser = sub.add_parser("send", help="Encrypt and send a message via DNS")
    send_parser.add_argument("--message", type=str, help="Plaintext message to send")
    send_parser.add_argument("--file", type=Path, help="Read message from file")
    send_parser.add_argument("--password", type=str, required=True)
    send_parser.add_argument("--base-domain", type=str, required=True)
    send_parser.add_argument("--server", type=str, default="8.8.8.8")
    send_parser.add_argument("--port", type=int, default=53)
    send_parser.add_argument("--chunk-size", type=int, default=15)
    send_parser.add_argument("--encoding", choices=["base32", "base64"], default="base32")
    send_parser.add_argument("--risk-window", type=int, default=5)
    send_parser.add_argument("--dry-run", action="store_true", help="Only print domains")
    send_parser.set_defaults(func=cmd_send)

    recv_parser = sub.add_parser("receive", help="Run DNS listener and decode payload")
    recv_parser.add_argument("--password", type=str, required=True)
    recv_parser.add_argument("--base-domain", type=str, required=True)
    recv_parser.add_argument("--encoding", choices=["base32", "base64"], default="base32")
    recv_parser.add_argument("--domains-file", type=str, help="File containing domains to decode")
    recv_parser.add_argument("--port", type=int, default=5353)
    recv_parser.add_argument("--response-ip", type=str, default="127.0.0.1")
    recv_parser.add_argument("--limit", type=int, help="Maximum number of domains to capture")
    recv_parser.add_argument("--timeout", type=float, help="Timeout for listening in seconds")
    recv_parser.add_argument("--output", type=Path, help="File to store recovered message")
    recv_parser.set_defaults(func=cmd_receive)

    tunnel_parser = sub.add_parser("tunnel", help="Prepare domains and send them")
    tunnel_parser.add_argument("--message", type=str, help="Plaintext message to send")
    tunnel_parser.add_argument("--file", type=Path, help="Read message from file")
    tunnel_parser.add_argument("--password", type=str, required=True)
    tunnel_parser.add_argument("--base-domain", type=str, required=True)
    tunnel_parser.add_argument("--server", type=str, default="8.8.8.8")
    tunnel_parser.add_argument("--port", type=int, default=53)
    tunnel_parser.add_argument("--chunk-size", type=int, default=15)
    tunnel_parser.add_argument("--encoding", choices=["base32", "base64"], default="base32")
    tunnel_parser.add_argument("--risk-window", type=int, default=5)
    tunnel_parser.add_argument("--print-only", action="store_true", help="Print the domains instead of sending")
    tunnel_parser.set_defaults(func=cmd_tunnel)

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as exc:  # pragma: no cover - CLI error path
        logger.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
