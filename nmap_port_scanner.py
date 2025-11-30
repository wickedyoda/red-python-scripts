#!/usr/bin/env python3
#Use these commands in Kali to install required software:
#  sudo apt install python3-pip
#  pip install python-nmap

"""Simple, educational port scanner using python-nmap.

The script keeps the original interactive prompts but also supports
command-line arguments for unattended use. Scan only systems you are
authorised to test.
"""

import argparse
import ipaddress
import re
from typing import Iterable, Tuple

import nmap


IP_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
PORT_RANGE_PATTERN = re.compile(r"([0-9]+)-([0-9]+)")


def validate_ip(ip_text: str) -> str:
    """Return a cleaned IPv4 string or raise ``argparse.ArgumentTypeError``."""

    if IP_PATTERN.fullmatch(ip_text):
        try:
            return str(ipaddress.ip_address(ip_text))
        except ValueError as exc:  # pragma: no cover - defensive guard
            raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {ip_text}") from exc
    raise argparse.ArgumentTypeError(f"Invalid IPv4 format: {ip_text}")


def parse_port_range(range_text: str) -> Tuple[int, int]:
    """Parse ``start-end`` input into a tuple of integers."""

    cleaned = range_text.replace(" ", "")
    match = PORT_RANGE_PATTERN.fullmatch(cleaned)
    if not match:
        raise argparse.ArgumentTypeError(
            "Port range must look like '20-80' (numbers between 0 and 65535)."
        )
    start, end = int(match.group(1)), int(match.group(2))
    if not (0 <= start <= end <= 65535):
        raise argparse.ArgumentTypeError("Port numbers must be between 0 and 65535.")
    return start, end


def prompt_for_ip() -> str:
    while True:
        ip_entered = input("\nPlease enter the IP address that you want to scan: ")
        try:
            return validate_ip(ip_entered)
        except argparse.ArgumentTypeError as exc:
            print(exc)


def prompt_for_port_range() -> Tuple[int, int]:
    while True:
        print(
            "Please enter the range of ports you want to scan in format: <int>-<int> "
            "(e.g. 60-120)"
        )
        port_range = input("Enter port range: ")
        try:
            return parse_port_range(port_range)
        except argparse.ArgumentTypeError as exc:
            print(exc)


def scan_ports(
    ip_address: str, port_start: int, port_end: int, timeout_seconds: int
) -> Iterable[Tuple[int, str]]:
    """Yield port numbers with their status from python-nmap."""

    nm = nmap.PortScanner()
    for port in range(port_start, port_end + 1):
        try:
            result = nm.scan(
                ip_address,
                str(port),
                arguments=f"--host-timeout {timeout_seconds}s",
            )
            port_status = result["scan"][ip_address]["tcp"][port]["state"]
        except Exception:
            yield port, "error"
        else:
            yield port, port_status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Simple educational port scanner using python-nmap")
    parser.add_argument("ip", nargs="?", type=validate_ip, help="IPv4 address to scan")
    parser.add_argument(
        "ports",
        nargs="?",
        type=parse_port_range,
        help="Port range in start-end format (example: 20-80)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3,
        help="Scan timeout per port in seconds passed through to nmap (default: 3)",
    )
    return parser


def main() -> None:
    print(r"""______            _     _  ______                 _           _
|  _  \          (_)   | | | ___ \               | |         | |
| | | |__ ___   ___  __| | | |_/ / ___  _ __ ___ | |__   __ _| |
| | | / _` \ \ / / |/ _` | | ___ \/ _ \| '_ ` _ \| '_ \ / _` | |
| |/ / (_| |\ V /| | (_| | | |_/ / (_) | | | | | | |_) | (_| | |
|___/ \__,_| \_/ |_|\__,_| \____/ \___/|_| |_| |_|_.__/ \__,_|_|""")
    print("\n****************************************************************")
    print("\n* Copyright of David Bombal, 2021                              *")
    print("\n* https://www.davidbombal.com                                  *")
    print("\n* https://www.youtube.com/davidbombal                          *")
    print("\n****************************************************************")
    print("\nScan only systems you are authorised to assess.")

    parser = build_parser()
    args = parser.parse_args()

    ip_address = args.ip or prompt_for_ip()
    port_min, port_max = args.ports or prompt_for_port_range()

    print(f"\nScanning {ip_address} on ports {port_min}-{port_max}...\n")

    for port, status in scan_ports(ip_address, port_min, port_max, args.timeout):
        if status == "error":
            print(f"Cannot scan port {port}.")
        else:
            print(f"Port {port} is {status}")


if __name__ == "__main__":
    main()
        
