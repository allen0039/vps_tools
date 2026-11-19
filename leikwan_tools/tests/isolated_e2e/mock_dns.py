#!/usr/bin/env python3
"""Lightweight UDP/53 mock DNS server reading dynamic A records from a JSON control file."""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct


def _read_name(packet: bytes, offset: int):
    labels = []
    pos = offset
    while pos < len(packet):
        length = packet[pos]
        pos += 1
        if length == 0:
            break
        labels.append(packet[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels).lower(), pos


def build_response(query: bytes, records_map: dict) -> bytes:
    if len(query) < 12:
        return b""
    txid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query[:12])
    if qdcount < 1:
        return b""
    qname, pos = _read_name(query, 12)
    qtype, qclass = struct.unpack("!HH", query[pos : pos + 4])
    question_bytes = query[12 : pos + 4]

    ips = records_map.get(qname, []) if (qtype == 1 and qclass == 1) else []
    resp_flags = 0x8180 | (flags & 0x0100)
    header = struct.pack("!HHHHHH", txid, resp_flags, 1, len(ips), 0, 0)
    answers = bytearray()
    for ip in ips:
        answers.extend(b"\xc0\x0c")
        answers.extend(struct.pack("!HHIH", 1, 1, 60, 4))
        answers.extend(ipaddress.IPv4Address(ip).packed)
    return header + question_bytes + bytes(answers)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="203.0.113.1")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--records-file", default="/tmp/dns_records.json")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen, args.port))

    while True:
        data, addr = sock.recvfrom(2048)
        try:
            raw = json.loads(Path(args.records_file).read_text(encoding="utf-8"))
            records_map = {k.lower().rstrip("."): v for k, v in raw.items()}
        except Exception:
            records_map = {}
        resp = build_response(data, records_map)
        if resp:
            sock.sendto(resp, addr)


if __name__ == "__main__":
    main()
