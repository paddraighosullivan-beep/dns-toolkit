#!/usr/bin/env python3
"""
dns-health - DNS Health Monitor & Smart Switcher
Monitors your DNS resolvers and finds alternatives when they degrade.

Continuously checks if your configured DNS resolvers are healthy. When a
resolver is slow or down, automatically finds the fastest alternative from
publicdns.info's live-tested directory.

Usage:
    python3 dns_health.py check                # One-time health check
    python3 dns_health.py monitor              # Continuous monitoring (Ctrl+C to stop)
    python3 dns_health.py monitor --interval 60  # Check every 60 seconds
    python3 dns_health.py find-best            # Find best DNS for your location
    python3 dns_health.py find-best --country US # Find best US DNS
    python3 dns_health.py pihole-update        # Update Pi-hole upstream DNS

Data source: https://publicdns.info (8,500+ live-tested resolvers)
"""

import argparse
import csv
import io
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

__version__ = "1.0.0"
__author__ = "Paddraigh O'Sullivan"
__url__ = "https://github.com/paddraighosullivan-beep/dns-toolkit"

PUBLICDNS_CSV_URL = "https://publicdns.info/nameservers.csv"
PUBLICDNS_SITE = "https://publicdns.info"
LOG_FILE = os.path.expanduser("~/.dns-health.log")
STATE_FILE = os.path.expanduser("~/.dns-health-state.json")

# Health thresholds
LATENCY_WARNING_MS = 100   # Above this = warning
LATENCY_CRITICAL_MS = 500  # Above this = critical
FAILURE_THRESHOLD = 3      # Consecutive failures before alert
JITTER_WARNING_MS = 50     # Jitter above this = warning

# Well-known fallback resolvers
FALLBACK_RESOLVERS = [
    {"ip": "1.1.1.1", "name": "Cloudflare"},
    {"ip": "8.8.8.8", "name": "Google Public DNS"},
    {"ip": "9.9.9.9", "name": "Quad9"},
    {"ip": "208.67.222.222", "name": "OpenDNS"},
    {"ip": "94.140.14.14", "name": "AdGuard DNS"},
]

TEST_DOMAINS = ["google.com", "cloudflare.com", "github.com"]

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    DIM = "\033[2m"

    @classmethod
    def disable(cls):
        for attr in ["RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "DIM"]:
            setattr(cls, attr, "")


def build_dns_query(domain: str) -> tuple:
    """Build a raw DNS A record query packet. Returns (txn_id, packet_bytes)."""
    if not domain or not domain.strip():
        return (0, b"")
    txn_id = random.randint(0, 65535)
    flags = 0x0100
    header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        if not label:
            continue
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError:
            try:
                encoded = label.encode("idna")
            except (UnicodeError, UnicodeDecodeError):
                return (0, b"")
        if len(encoded) > 63:
            encoded = encoded[:63]
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    question += struct.pack(">HH", 1, 1)
    return (txn_id, header + question)


def dns_query(server: str, domain: str, timeout: float = 3.0) -> Optional[float]:
    """Send DNS query, return latency in ms or None on failure."""
    txn_id, query = build_dns_query(domain)
    if not query:
        return None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start) * 1000
        if len(data) >= 2:
            resp_id = struct.unpack(">H", data[:2])[0]
            if resp_id != txn_id:
                return None
        return elapsed
    except (socket.timeout, socket.error, OSError, Exception):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def check_resolver(server: str, timeout: float = 3.0) -> dict:
    """Run a quick health check on a single resolver."""
    latencies = []
    failures = 0

    for domain in TEST_DOMAINS:
        result = dns_query(server, domain, timeout)
        if result is not None:
            latencies.append(result)
        else:
            failures += 1

    if not latencies:
        return {
            "server": server,
            "status": "DOWN",
            "avg_ms": None,
            "jitter_ms": None,
            "reliability": 0.0,
            "failures": failures,
            "total": len(TEST_DOMAINS),
        }

    avg = sum(latencies) / len(latencies)
    if len(latencies) >= 2:
        jitter = (sum((x - avg) ** 2 for x in latencies) / len(latencies)) ** 0.5
    else:
        jitter = 0.0

    if avg > LATENCY_CRITICAL_MS:
        status = "CRITICAL"
    elif avg > LATENCY_WARNING_MS or jitter > JITTER_WARNING_MS:
        status = "WARNING"
    elif failures > 0:
        status = "DEGRADED"
    else:
        status = "HEALTHY"

    return {
        "server": server,
        "status": status,
        "avg_ms": round(avg, 2),
        "jitter_ms": round(jitter, 2),
        "reliability": round((len(TEST_DOMAINS) - failures) / len(TEST_DOMAINS) * 100, 1),
        "failures": failures,
        "total": len(TEST_DOMAINS),
    }


def get_system_dns() -> list:
    """Detect system DNS resolvers from resolv.conf or OS settings."""
    resolvers = []

    # Linux/macOS: parse /etc/resolv.conf
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            if ":" not in ip:  # IPv4 only
                                try:
                                    socket.inet_aton(ip)
                                    resolvers.append(ip)
                                except socket.error:
                                    pass
        except PermissionError:
            pass

    # Fallback: try systemd-resolve
    if not resolvers:
        try:
            result = subprocess.run(
                ["resolvectl", "dns"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    for part in parts:
                        try:
                            socket.inet_aton(part)
                            resolvers.append(part)
                        except socket.error:
                            continue
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for r in resolvers:
        if r not in seen:
            seen.add(r)
            unique.append(r)

    return unique


def fetch_best_resolvers(country: str = None, limit: int = 10) -> list:
    """Fetch top resolvers from publicdns.info for the given country."""
    try:
        import urllib.request
        req = urllib.request.Request(
            PUBLICDNS_CSV_URL,
            headers={"User-Agent": f"dns-health/{__version__} (+{__url__})"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8")
    except Exception:
        return FALLBACK_RESOLVERS[:limit]

    resolvers = []
    reader = csv.DictReader(io.StringIO(data))
    for row in reader:
        ip = row.get("ip_address", "").strip()
        if not ip or ":" in ip:
            continue

        cc = row.get("country_code", "").strip()
        if country and cc.upper() != country.upper():
            continue

        reliability = 0.0
        try:
            reliability = float(row.get("reliability", "0"))
        except (ValueError, TypeError):
            pass

        if reliability < 0.8:
            continue

        resolvers.append({
            "ip": ip,
            "name": row.get("name", "").strip() or row.get("as_org", "").strip(),
            "country": cc,
            "reliability": reliability,
        })

    resolvers.sort(key=lambda x: x["reliability"], reverse=True)
    return resolvers[:limit]


def detect_country() -> str:
    """Detect user's country."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("country", "")
    except Exception:
        return ""


def log_event(message: str, level: str = "INFO"):
    """Log an event to file and optionally stdout."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def save_state(state: dict):
    """Save monitoring state to file."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except OSError:
        pass


def load_state() -> dict:
    """Load monitoring state from file."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def print_banner():
    """Print tool banner."""
    print(f"""
{Color.BOLD}{Color.CYAN}╔══════════════════════════════════════════════════╗
║           dns-health v{__version__}                       ║
║   DNS Health Monitor & Smart Switcher            ║
║   Data: publicdns.info                           ║
╚══════════════════════════════════════════════════╝{Color.RESET}
""")


def cmd_check(args):
    """Run a one-time health check on system DNS resolvers."""
    print_banner()

    system_dns = get_system_dns()
    if not system_dns:
        print(f"{Color.YELLOW}Could not detect system DNS. Checking well-known resolvers instead.{Color.RESET}")
        system_dns = [r["ip"] for r in FALLBACK_RESOLVERS[:3]]

    print(f"{Color.BOLD}Checking {len(system_dns)} configured DNS resolver(s)...{Color.RESET}\n")

    all_healthy = True
    for server in system_dns:
        result = check_resolver(server)

        if result["status"] == "HEALTHY":
            icon = f"{Color.GREEN}✓ HEALTHY{Color.RESET}"
        elif result["status"] == "DEGRADED":
            icon = f"{Color.YELLOW}⚠ DEGRADED{Color.RESET}"
            all_healthy = False
        elif result["status"] == "WARNING":
            icon = f"{Color.YELLOW}⚠ WARNING{Color.RESET}"
            all_healthy = False
        elif result["status"] == "CRITICAL":
            icon = f"{Color.RED}✗ CRITICAL{Color.RESET}"
            all_healthy = False
        else:
            icon = f"{Color.RED}✗ DOWN{Color.RESET}"
            all_healthy = False

        print(f"  {icon}  {server}")
        if result["avg_ms"] is not None:
            print(f"         Latency: {result['avg_ms']:.1f}ms | Jitter: {result['jitter_ms']:.1f}ms | Reliability: {result['reliability']:.0f}%")
        else:
            print(f"         {Color.RED}No response — resolver is unreachable{Color.RESET}")
        print()

    if not all_healthy:
        print(f"{Color.YELLOW}Some resolvers are not healthy. Run 'dns-health find-best' to find alternatives.{Color.RESET}")
        print(f"{Color.DIM}Or visit {PUBLICDNS_SITE}/dns-gaming-benchmark.html for a web-based speed test.{Color.RESET}")
    else:
        print(f"{Color.GREEN}All DNS resolvers are healthy.{Color.RESET}")

    return 0 if all_healthy else 1


def cmd_find_best(args):
    """Find the best DNS resolvers for the user's location."""
    print_banner()

    country = args.country
    if not country:
        country = detect_country()
        if country:
            print(f"{Color.DIM}Detected country: {country}{Color.RESET}")

    print(f"{Color.DIM}Fetching resolver candidates from publicdns.info...{Color.RESET}")
    candidates = fetch_best_resolvers(country=country, limit=30)

    if not candidates:
        print(f"{Color.RED}No resolvers found. Try without --country filter.{Color.RESET}")
        return 1

    print(f"{Color.BOLD}Testing {min(len(candidates), args.top)} resolvers...{Color.RESET}\n")

    results = []
    for resolver in candidates[:args.top]:
        result = check_resolver(resolver["ip"])
        result["name"] = resolver.get("name", "")
        result["country"] = resolver.get("country", "")
        results.append(result)

    # Sort by latency (healthy ones first)
    working = [r for r in results if r["status"] != "DOWN"]
    working.sort(key=lambda x: x["avg_ms"])

    print(f"{'#':>3}  {'Server':<18} {'Name':<22} {'Latency':>8} {'Jitter':>8} {'Status':<10}")
    print(f"{'─'*3}  {'─'*18} {'─'*22} {'─'*8} {'─'*8} {'─'*10}")

    for i, r in enumerate(working[:15], 1):
        if r["status"] == "HEALTHY":
            color = Color.GREEN
        elif r["status"] in ("WARNING", "DEGRADED"):
            color = Color.YELLOW
        else:
            color = Color.RED

        name = r.get("name", "")[:22]
        print(f"{color}{i:>3}  {r['server']:<18} {name:<22} {r['avg_ms']:>6.1f}ms {r['jitter_ms']:>6.1f}ms {r['status']:<10}{Color.RESET}")

    if working:
        best = working[0]
        second = working[1] if len(working) > 1 else None

        print(f"\n{Color.BOLD}{Color.GREEN}Recommended DNS configuration:{Color.RESET}")
        print(f"  Primary:   {best['server']}  ({best.get('name', '')})")
        if second:
            print(f"  Secondary: {second['server']}  ({second.get('name', '')})")

        print(f"\n{Color.DIM}To set on Linux:  sudo sh -c 'echo \"nameserver {best['server']}\" > /etc/resolv.conf'")
        if second:
            print(f"                  sudo sh -c 'echo \"nameserver {second['server']}\" >> /etc/resolv.conf'")
        print(f"Web speed test:   {PUBLICDNS_SITE}/dns-gaming-benchmark.html{Color.RESET}")


def cmd_monitor(args):
    """Continuously monitor DNS health."""
    print_banner()

    system_dns = get_system_dns()
    if not system_dns:
        print(f"{Color.YELLOW}No system DNS detected. Monitoring well-known resolvers.{Color.RESET}")
        system_dns = [r["ip"] for r in FALLBACK_RESOLVERS[:3]]

    print(f"{Color.BOLD}Monitoring {len(system_dns)} resolver(s) every {args.interval}s (Ctrl+C to stop){Color.RESET}")
    print(f"{Color.DIM}Log file: {LOG_FILE}{Color.RESET}\n")

    state = load_state()
    consecutive_failures = {ip: 0 for ip in system_dns}
    check_count = 0

    try:
        while True:
            check_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            any_issue = False

            for server in system_dns:
                result = check_resolver(server)
                status = result["status"]

                if status == "HEALTHY":
                    icon = f"{Color.GREEN}✓{Color.RESET}"
                    consecutive_failures[server] = 0
                elif status in ("DOWN", "CRITICAL"):
                    icon = f"{Color.RED}✗{Color.RESET}"
                    consecutive_failures[server] = consecutive_failures.get(server, 0) + 1
                    any_issue = True
                else:
                    icon = f"{Color.YELLOW}⚠{Color.RESET}"
                    any_issue = True

                latency_str = f"{result['avg_ms']:.0f}ms" if result['avg_ms'] is not None else "FAIL"
                print(f"  [{timestamp}] {icon} {server:<18} {latency_str:>7}  {status}")

                # Log events
                if status != "HEALTHY":
                    log_event(f"{server} status={status} avg={result.get('avg_ms', 'N/A')}ms", "WARN")

                # Alert on consecutive failures
                if consecutive_failures.get(server, 0) >= FAILURE_THRESHOLD:
                    print(f"\n  {Color.RED}{Color.BOLD}ALERT: {server} has failed {consecutive_failures[server]} consecutive checks!{Color.RESET}")
                    log_event(f"ALERT: {server} failed {consecutive_failures[server]} consecutive checks", "CRITICAL")

                    print(f"  {Color.YELLOW}Finding alternatives from publicdns.info...{Color.RESET}")
                    alts = fetch_best_resolvers(limit=3)
                    for alt in alts:
                        alt_check = check_resolver(alt["ip"])
                        if alt_check["status"] == "HEALTHY":
                            print(f"  {Color.GREEN}Alternative: {alt['ip']} ({alt['name']}) - {alt_check['avg_ms']:.0f}ms{Color.RESET}")
                            log_event(f"Suggested alternative: {alt['ip']} ({alt['name']})", "INFO")
                    print()

                    # Reset counter after alerting
                    consecutive_failures[server] = 0

            # Save state
            state["last_check"] = datetime.utcnow().isoformat() + "Z"
            state["check_count"] = check_count
            state["resolvers"] = system_dns
            save_state(state)

            if not any_issue:
                sys.stdout.write(f"\r  [{timestamp}] All resolvers healthy (check #{check_count})")
                sys.stdout.flush()

            time.sleep(args.interval)
            if any_issue:
                print()

    except KeyboardInterrupt:
        print(f"\n\n{Color.DIM}Monitoring stopped. {check_count} checks performed.{Color.RESET}")
        print(f"{Color.DIM}Log: {LOG_FILE}{Color.RESET}")


def cmd_pihole_update(args):
    """Update Pi-hole upstream DNS with the fastest resolvers."""
    print_banner()

    # Check if Pi-hole is installed
    pihole_config = "/etc/pihole/setupVars.conf"
    if not os.path.exists(pihole_config):
        print(f"{Color.RED}Pi-hole not found at {pihole_config}{Color.RESET}")
        print(f"This command updates Pi-hole's upstream DNS servers.")
        return 1

    print(f"{Color.DIM}Fetching fastest resolvers from publicdns.info...{Color.RESET}")
    country = detect_country()
    candidates = fetch_best_resolvers(country=country, limit=20)

    results = []
    for resolver in candidates[:10]:
        result = check_resolver(resolver["ip"])
        result["name"] = resolver.get("name", "")
        if result["status"] != "DOWN":
            results.append(result)

    results.sort(key=lambda x: x["avg_ms"])

    if len(results) < 2:
        print(f"{Color.RED}Not enough healthy resolvers found.{Color.RESET}")
        return 1

    primary = results[0]
    secondary = results[1]

    print(f"\n{Color.BOLD}Recommended Pi-hole upstream DNS:{Color.RESET}")
    print(f"  Primary:   {primary['server']} ({primary.get('name', '')}) - {primary['avg_ms']:.0f}ms")
    print(f"  Secondary: {secondary['server']} ({secondary.get('name', '')}) - {secondary['avg_ms']:.0f}ms")

    print(f"\n{Color.YELLOW}To update Pi-hole, run:{Color.RESET}")
    print(f"  sudo pihole -a setdns {primary['server']} {secondary['server']}")
    print(f"\n{Color.DIM}Or edit {pihole_config} and set:")
    print(f"  PIHOLE_DNS_1={primary['server']}")
    print(f"  PIHOLE_DNS_2={secondary['server']}")
    print(f"Then: pihole restartdns{Color.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="dns-health - DNS Health Monitor & Smart Switcher. "
        "Monitors DNS resolvers and finds alternatives from publicdns.info.",
        epilog=f"Data: {PUBLICDNS_SITE} | Issues: {__url__}",
    )
    parser.add_argument("--version", action="version", version=f"dns-health {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # check command
    check_parser = subparsers.add_parser("check", help="One-time health check of system DNS")

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Continuous DNS monitoring")
    monitor_parser.add_argument("--interval", "-i", type=int, default=30, help="Check interval in seconds (default: 30)")

    # find-best command
    find_parser = subparsers.add_parser("find-best", help="Find the fastest DNS for your location")
    find_parser.add_argument("--country", "-c", type=str, help="Filter by country code (e.g., US, DE)")
    find_parser.add_argument("--top", "-t", type=int, default=15, help="Number of resolvers to test (default: 15)")

    # pihole-update command
    pihole_parser = subparsers.add_parser("pihole-update", help="Update Pi-hole upstream DNS")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Color.disable()

    # Validate arguments
    if args.command == "monitor" and args.interval < 1:
        parser.error("--interval must be at least 1 second")
    if args.command == "find-best" and hasattr(args, "top") and args.top < 1:
        parser.error("--top must be at least 1")

    if args.command == "check":
        return cmd_check(args)
    elif args.command == "monitor":
        return cmd_monitor(args)
    elif args.command == "find-best":
        return cmd_find_best(args)
    elif args.command == "pihole-update":
        return cmd_pihole_update(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
