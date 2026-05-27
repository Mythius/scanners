#!/usr/bin/env python3
import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "rpcbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt",
}


def check_port(ip: str, port: int, timeout: float) -> dict | None:
    """Return port info dict if open, else None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = SERVICE_NAMES.get(port, "")
            return {"port": port, "service": service}
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None


def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:80] if banner else ""
    except Exception:
        return ""


def scan_ports(
    ip: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 200,
    banners: bool = False,
) -> list[dict]:
    open_ports = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(check_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                if banners:
                    result["banner"] = grab_banner(ip, result["port"], timeout)
                open_ports.append(result)

    return sorted(open_ports, key=lambda r: r["port"])


def parse_ports(port_str: str) -> list[int]:
    """Parse '80,443,1000-2000' into a list of ints."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(description="Port scanner")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan: '80', '1-1024', '22,80,443' (default: common ports)",
        default=None,
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Scan all 65535 ports",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=200,
        help="Concurrent threads (default: 200)",
    )
    parser.add_argument(
        "-b", "--banners", action="store_true",
        help="Grab service banners from open ports",
    )
    args = parser.parse_args()

    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = COMMON_PORTS

    try:
        resolved = socket.gethostbyname(args.ip)
    except socket.gaierror:
        print(f"Error: cannot resolve '{args.ip}'")
        sys.exit(1)

    print(f"Target     : {args.ip} ({resolved})")
    print(f"Ports      : {len(ports)} port(s)")
    print(f"Timeout    : {args.timeout}s")
    print("-" * 50)

    open_ports = scan_ports(resolved, ports, args.timeout, args.workers, args.banners)

    if not open_ports:
        print("No open ports found.")
    else:
        print(f"{'PORT':<8} {'SERVICE':<12} {'BANNER'}")
        print("-" * 50)
        for entry in open_ports:
            banner = entry.get("banner", "")
            print(f"{entry['port']:<8} {entry['service']:<12} {banner}")

    print("-" * 50)
    print(f"Found {len(open_ports)} open port(s).")


if __name__ == "__main__":
    main()
