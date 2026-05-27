#!/usr/bin/env python3
import argparse
import ipaddress
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)


def get_local_network():
    """Detect local IP and derive the /24 subnet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(network), local_ip


def ping(ip: str) -> str | None:
    """Return the IP if it responds to ping, else None."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return str(ip) if result.returncode == 0 else None


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def get_arp_table() -> dict[str, str]:
    """Return a dict of {ip: mac} from the system ARP cache."""
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        output = result.stdout
        log.debug("Raw arp -a output:\n%s", output)
    except Exception as e:
        log.error("arp command failed: %s", e)
        return {}

    table = {}
    for line in output.splitlines():
        ip_match = re.search(r"\(?([\d.]+)\)?", line)
        mac_match = re.search(r"([\da-fA-F]{1,2}(?:[:\-][\da-fA-F]{1,2}){5})", line)
        log.debug("ARP line: %r | ip=%s mac=%s", line,
                  ip_match.group(1) if ip_match else None,
                  mac_match.group(1) if mac_match else None)
        if ip_match and mac_match:
            ip = ip_match.group(1)
            raw = mac_match.group(1).replace("-", ":")
            mac = ":".join(p.zfill(2) for p in raw.split(":"))
            log.debug("Parsed ARP entry: %s -> %s", ip, mac)
            table[ip] = mac
        else:
            log.debug("Skipped ARP line (no ip or mac match): %r", line)
    log.info("ARP table has %d entries", len(table))
    return table


def lookup_manufacturer(mac: str) -> str:
    """Look up NIC manufacturer via the macvendors.com API (free, 1 req/s)."""
    if not mac:
        log.debug("lookup_manufacturer called with empty MAC, skipping")
        return ""
    url = f"https://api.macvendors.com/{mac}"
    log.debug("Querying manufacturer for MAC %s -> %s", mac, url)
    try:
        # Use curl so macOS system certificates are used automatically.
        result = subprocess.run(
            ["curl", "-s", "--max-time", "4", "-w", "\n%{http_code}", url],
            capture_output=True, text=True,
        )
        *body_lines, status_line = result.stdout.strip().splitlines()
        status = int(status_line) if status_line.isdigit() else 0
        body = "\n".join(body_lines).strip()
        log.debug("MAC %s -> HTTP %d body=%r", mac, status, body)
        if status == 200:
            log.info("MAC %s -> vendor: %s", mac, body)
            return body
        if status == 404:
            log.warning("HTTP 404 for MAC %s (no OUI record — likely randomized)", mac)
            return "Unknown"
        log.warning("Unexpected HTTP %d for MAC %s", status, mac)
        return ""
    except Exception as e:
        log.error("Manufacturer lookup failed for %s: %s", mac, e)
        return ""


def scan_network(network: str, workers: int = 100, details: bool = False) -> list[dict]:
    hosts = list(ipaddress.IPv4Network(network).hosts())
    print(f"Scanning {len(hosts)} hosts on {network} ...\n")

    live_hosts = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(ping, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                hostname = resolve_hostname(result)
                live_hosts.append({"ip": result, "hostname": hostname, "mac": "", "vendor": ""})
                label = f" ({hostname})" if hostname else ""
                print(f"  [UP] {result}{label}")

    live_hosts = sorted(live_hosts, key=lambda h: socket.inet_aton(h["ip"]))

    if details and live_hosts:
        print("\nResolving MAC addresses ...")
        arp_table = get_arp_table()
        for host in live_hosts:
            mac = arp_table.get(host["ip"], "")
            host["mac"] = mac
            log.info("Host %s -> MAC: %r", host["ip"], mac or "(not found in ARP table)")

        print("Looking up manufacturers (rate-limited to 1/s) ...")
        for host in live_hosts:
            host["vendor"] = lookup_manufacturer(host["mac"])
            if host["mac"]:
                time.sleep(1)  # respect free-tier rate limit

    return live_hosts


def print_results(live: list[dict], details: bool) -> None:
    print()
    if details:
        col = f"{'IP':<16} {'HOSTNAME':<30} {'MAC':<18} {'MANUFACTURER'}"
        print(col)
        print("-" * 80)
        for h in live:
            print(f"{h['ip']:<16} {h['hostname']:<30} {h['mac'] or '?':<18} {h['vendor']}")
    else:
        col = f"{'IP':<16} {'HOSTNAME'}"
        print(col)
        print("-" * 50)
        for h in live:
            print(f"{h['ip']:<16} {h['hostname']}")


def main():
    parser = argparse.ArgumentParser(description="Local network IP scanner")
    parser.add_argument(
        "--details",
        action="store_true",
        help="Also show MAC address and NIC manufacturer for each live host",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100,
        help="Concurrent ping threads (default: 100)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(funcName)s: %(message)s",
    )

    network, local_ip = get_local_network()
    print(f"Local IP   : {local_ip}")
    print(f"Network    : {network}")
    print("-" * 40)

    live = scan_network(network, workers=args.workers, details=args.details)

    print_results(live, args.details)
    print("-" * (80 if args.details else 50))
    print(f"Found {len(live)} live host(s).")


if __name__ == "__main__":
    main()
