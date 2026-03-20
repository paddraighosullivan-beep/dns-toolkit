#!/usr/bin/env python3
"""
dns-bench - Cross-platform DNS Benchmark Tool
Finds the fastest DNS resolver for YOUR location.

Pulls live-tested resolvers from publicdns.info and benchmarks them
from your actual network. Supports gaming mode, privacy filter,
country filter, and custom resolver lists.

Usage:
    python3 dns_bench.py                    # Quick benchmark (top 20 resolvers)
    python3 dns_bench.py --country US       # Test US resolvers only
    python3 dns_bench.py --gaming           # Gaming mode (latency + jitter focus)
    python3 dns_bench.py --privacy          # Only DNSSEC-enabled resolvers
    python3 dns_bench.py --all              # Test ALL resolvers (slow but thorough)
    python3 dns_bench.py --top 50           # Test top 50 resolvers
    python3 dns_bench.py --export results.json  # Export results to JSON
    python3 dns_bench.py --export results.csv   # Export results to CSV

Data source: https://publicdns.info (8,500+ live-tested public DNS servers)
"""

import argparse
import csv
import io
import json
import os
import random
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

__version__ = "1.0.0"
__author__ = "Paddraigh O'Sullivan"
__url__ = "https://github.com/paddraighosullivan-beep/dns-toolkit"

PUBLICDNS_CSV_URL = "https://publicdns.info/nameservers.csv"
PUBLICDNS_SITE = "https://publicdns.info"

# Well-known resolvers to always include
WELL_KNOWN = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS (Secondary)",
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare (Secondary)",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9 (Secondary)",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS (Secondary)",
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS (Secondary)",
    "185.228.168.9": "CleanBrowsing",
    "185.228.169.9": "CleanBrowsing (Secondary)",
    "76.76.19.19": "Alternate DNS",
    "76.223.122.150": "Alternate DNS (Secondary)",
    "64.6.64.6": "Verisign",
    "64.6.65.6": "Verisign (Secondary)",
    "156.154.70.5": "Neustar UltraDNS",
    "156.154.71.5": "Neustar UltraDNS (Secondary)",
}

# Test domains for benchmarking (mix of popular + less cached)
TEST_DOMAINS = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "github.com",
    "cloudflare.com",
    "wikipedia.org",
    "reddit.com",
    "stackoverflow.com",
    "microsoft.com",
    "apple.com",
]

# Domains unlikely to be cached (for cold-cache testing)
COLD_DOMAINS = [
    f"bench-{random.randint(10000,99999)}.example.com",
    f"test-{random.randint(10000,99999)}.nonexistent.invalid",
]

# ANSI color codes
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


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a raw DNS query packet. qtype=1 for A record."""
    txn_id = random.randint(0, 65535)
    flags = 0x0100  # Standard query with recursion desired
    header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

    question = b""
    for label in domain.split("."):
        encoded = label.encode("ascii")
        question += struct.pack("B", len(encoded)) + encoded
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN

    return header + question


def dns_query(server: str, domain: str, timeout: float = 3.0) -> Optional[float]:
    """Send a DNS query and return response time in ms, or None on failure."""
    query = build_dns_query(domain)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(query, (server, 53))
        sock.recvfrom(1024)
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        return elapsed
    except (socket.timeout, socket.error, OSError):
        try:
            sock.close()
        except Exception:
            pass
        return None


def benchmark_server(server: str, domains: list, rounds: int = 3, timeout: float = 3.0) -> dict:
    """Benchmark a single DNS server with multiple queries."""
    latencies = []
    failures = 0
    total_queries = 0

    for _ in range(rounds):
        for domain in domains:
            total_queries += 1
            result = dns_query(server, domain, timeout)
            if result is not None:
                latencies.append(result)
            else:
                failures += 1

    if not latencies:
        return {
            "server": server,
            "avg_ms": float("inf"),
            "min_ms": float("inf"),
            "max_ms": float("inf"),
            "jitter_ms": float("inf"),
            "reliability": 0.0,
            "queries": total_queries,
            "failures": failures,
            "status": "TIMEOUT",
        }

    avg = sum(latencies) / len(latencies)
    jitter = (sum((x - avg) ** 2 for x in latencies) / len(latencies)) ** 0.5

    return {
        "server": server,
        "avg_ms": round(avg, 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
        "jitter_ms": round(jitter, 2),
        "reliability": round((total_queries - failures) / total_queries * 100, 1),
        "queries": total_queries,
        "failures": failures,
        "status": "OK" if failures == 0 else "PARTIAL",
    }


def fetch_resolvers(country: str = None, dnssec_only: bool = False, limit: int = None) -> list:
    """Fetch resolver list from publicdns.info CSV."""
    try:
        import urllib.request

        print(f"{Color.DIM}Fetching resolver list from publicdns.info...{Color.RESET}")
        req = urllib.request.Request(
            PUBLICDNS_CSV_URL,
            headers={"User-Agent": f"dns-bench/{__version__} (+{__url__})"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8")
    except Exception as e:
        print(f"{Color.YELLOW}Warning: Could not fetch from publicdns.info: {e}{Color.RESET}")
        print(f"{Color.DIM}Using built-in well-known resolvers only.{Color.RESET}")
        return [{"ip": ip, "name": name, "country": "??", "org": "", "dnssec": False, "reliability": 1.0}
                for ip, name in WELL_KNOWN.items() if ":" not in ip]

    resolvers = []
    reader = csv.DictReader(io.StringIO(data))
    for row in reader:
        ip = row.get("ip_address", "").strip()
        if not ip or ":" in ip:  # Skip IPv6 for now
            continue

        cc = row.get("country_code", "").strip()
        if country and cc.upper() != country.upper():
            continue

        dnssec = row.get("dnssec", "").strip().lower() == "true"
        if dnssec_only and not dnssec:
            continue

        reliability = 0.0
        try:
            reliability = float(row.get("reliability", "0"))
        except (ValueError, TypeError):
            pass

        if reliability < 0.5:
            continue

        resolvers.append({
            "ip": ip,
            "name": row.get("name", "").strip(),
            "country": cc,
            "org": row.get("as_org", "").strip(),
            "dnssec": dnssec,
            "reliability": reliability,
        })

    # Sort by reliability (most reliable first)
    resolvers.sort(key=lambda x: x["reliability"], reverse=True)

    if limit:
        resolvers = resolvers[:limit]

    return resolvers


def detect_country() -> str:
    """Try to detect user's country via IP geolocation."""
    try:
        import urllib.request
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("country", "")
    except Exception:
        return ""


def gaming_score(result: dict) -> float:
    """Calculate a gaming-focused score. Lower latency + lower jitter = better."""
    if result["status"] == "TIMEOUT":
        return 0.0
    # Gaming score: 40% latency, 40% jitter, 20% reliability
    latency_score = max(0, 100 - result["avg_ms"]) / 100
    jitter_score = max(0, 50 - result["jitter_ms"]) / 50
    rel_score = result["reliability"] / 100
    return round(latency_score * 0.4 + jitter_score * 0.4 + rel_score * 0.2, 3) * 100


def print_banner():
    """Print the tool banner."""
    print(f"""
{Color.BOLD}{Color.CYAN}╔══════════════════════════════════════════════════╗
║           dns-bench v{__version__}                        ║
║   Cross-Platform DNS Benchmark Tool              ║
║   Data: publicdns.info (8,500+ resolvers)        ║
╚══════════════════════════════════════════════════╝{Color.RESET}
""")


def print_results(results: list, gaming_mode: bool = False):
    """Print benchmark results in a formatted table."""
    # Filter out timeouts for display, keep them at bottom
    working = [r for r in results if r["status"] != "TIMEOUT"]
    failed = [r for r in results if r["status"] == "TIMEOUT"]

    if gaming_mode:
        working.sort(key=lambda x: gaming_score(x), reverse=True)
    else:
        working.sort(key=lambda x: x["avg_ms"])

    all_sorted = working + failed

    # Header
    if gaming_mode:
        print(f"\n{Color.BOLD}{'#':>3}  {'Server':<18} {'Name':<25} {'Avg':>7} {'Jitter':>7} {'Rel':>6} {'Game':>6} {'Status':<8}{Color.RESET}")
        print(f"{'─'*3}  {'─'*18} {'─'*25} {'─'*7} {'─'*7} {'─'*6} {'─'*6} {'─'*8}")
    else:
        print(f"\n{Color.BOLD}{'#':>3}  {'Server':<18} {'Name':<25} {'Avg':>7} {'Min':>7} {'Max':>7} {'Jitter':>7} {'Rel':>6} {'Status':<8}{Color.RESET}")
        print(f"{'─'*3}  {'─'*18} {'─'*25} {'─'*7} {'─'*7} {'─'*7} {'─'*7} {'─'*6} {'─'*8}")

    for i, r in enumerate(all_sorted[:50], 1):
        server = r["server"]
        name = r.get("display_name", WELL_KNOWN.get(server, r.get("org", "")))[:25]

        if r["status"] == "TIMEOUT":
            color = Color.RED
            avg_str = "FAIL"
            min_str = max_str = jitter_str = rel_str = game_str = "—"
        else:
            avg = r["avg_ms"]
            if avg < 20:
                color = Color.GREEN
            elif avg < 50:
                color = Color.CYAN
            elif avg < 100:
                color = Color.YELLOW
            else:
                color = Color.RED

            avg_str = f"{avg:.1f}ms"
            min_str = f"{r['min_ms']:.1f}ms"
            max_str = f"{r['max_ms']:.1f}ms"
            jitter_str = f"{r['jitter_ms']:.1f}ms"
            rel_str = f"{r['reliability']:.0f}%"
            game_str = f"{gaming_score(r):.0f}"

        status_color = Color.GREEN if r["status"] == "OK" else (Color.YELLOW if r["status"] == "PARTIAL" else Color.RED)

        if gaming_mode:
            print(f"{color}{i:>3}  {server:<18} {name:<25} {avg_str:>7} {jitter_str:>7} {rel_str:>6} {game_str:>6} {status_color}{r['status']:<8}{Color.RESET}")
        else:
            print(f"{color}{i:>3}  {server:<18} {name:<25} {avg_str:>7} {min_str:>7} {max_str:>7} {jitter_str:>7} {rel_str:>6} {status_color}{r['status']:<8}{Color.RESET}")

    # Summary
    if working:
        best = working[0]
        print(f"\n{Color.BOLD}{Color.GREEN}★ Fastest: {best['server']}")
        name = WELL_KNOWN.get(best["server"], best.get("org", ""))
        if name:
            print(f"  Provider: {name}")
        print(f"  Average: {best['avg_ms']:.1f}ms | Jitter: {best['jitter_ms']:.1f}ms | Reliability: {best['reliability']:.0f}%{Color.RESET}")

        if gaming_mode:
            best_gaming = max(working, key=lambda x: gaming_score(x))
            if best_gaming["server"] != best["server"]:
                print(f"\n{Color.BOLD}{Color.CYAN}🎮 Best for Gaming: {best_gaming['server']}")
                gname = WELL_KNOWN.get(best_gaming["server"], best_gaming.get("org", ""))
                if gname:
                    print(f"  Provider: {gname}")
                print(f"  Score: {gaming_score(best_gaming):.0f}/100 | Latency: {best_gaming['avg_ms']:.1f}ms | Jitter: {best_gaming['jitter_ms']:.1f}ms{Color.RESET}")

    print(f"\n{Color.DIM}Tested {len(results)} resolvers | {len(working)} responded | {len(failed)} timed out")
    print(f"Data source: {PUBLICDNS_SITE}")
    print(f"Run 'dns-bench --gaming' for gaming-optimized rankings{Color.RESET}")


def export_results(results: list, filepath: str, gaming_mode: bool = False):
    """Export results to JSON or CSV."""
    for r in results:
        r["display_name"] = WELL_KNOWN.get(r["server"], r.get("org", ""))
        if gaming_mode:
            r["gaming_score"] = gaming_score(r)

    if filepath.endswith(".json"):
        output = {
            "tool": f"dns-bench v{__version__}",
            "source": PUBLICDNS_SITE,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "results": results,
        }
        with open(filepath, "w") as f:
            json.dump(output, f, indent=2)
    elif filepath.endswith(".csv"):
        fields = ["server", "display_name", "avg_ms", "min_ms", "max_ms", "jitter_ms", "reliability", "status"]
        if gaming_mode:
            fields.append("gaming_score")
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
    else:
        print(f"{Color.RED}Error: Export format must be .json or .csv{Color.RESET}")
        return

    print(f"{Color.GREEN}Results exported to {filepath}{Color.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="dns-bench - Cross-platform DNS benchmark tool. "
        "Finds the fastest DNS resolver for your location using live data from publicdns.info.",
        epilog=f"Data source: {PUBLICDNS_SITE} | Report issues: {__url__}",
    )
    parser.add_argument("--version", action="version", version=f"dns-bench {__version__}")
    parser.add_argument("--country", "-c", type=str, help="Filter resolvers by country code (e.g., US, DE, IE)")
    parser.add_argument("--gaming", "-g", action="store_true", help="Gaming mode: rank by latency + jitter consistency")
    parser.add_argument("--privacy", "-p", action="store_true", help="Only test DNSSEC-enabled resolvers")
    parser.add_argument("--top", "-t", type=int, default=20, help="Number of resolvers to test (default: 20)")
    parser.add_argument("--all", "-a", action="store_true", help="Test ALL available resolvers (slow)")
    parser.add_argument("--rounds", "-r", type=int, default=3, help="Number of test rounds per resolver (default: 3)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Query timeout in seconds (default: 3.0)")
    parser.add_argument("--threads", "-j", type=int, default=10, help="Concurrent test threads (default: 10)")
    parser.add_argument("--export", "-e", type=str, help="Export results to file (.json or .csv)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output (just top 5)")
    parser.add_argument("--custom", type=str, help="Comma-separated list of custom DNS servers to test")

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Color.disable()

    if not args.quiet:
        print_banner()

    # Build resolver list
    resolvers = []

    if args.custom:
        # Custom servers only
        for ip in args.custom.split(","):
            ip = ip.strip()
            if ip:
                resolvers.append({
                    "ip": ip,
                    "name": WELL_KNOWN.get(ip, ""),
                    "country": "??",
                    "org": WELL_KNOWN.get(ip, "Custom"),
                    "dnssec": False,
                    "reliability": 1.0,
                })
    else:
        # Auto-detect country if not specified
        country = args.country
        if not country and not args.all:
            detected = detect_country()
            if detected:
                print(f"{Color.DIM}Detected country: {detected}{Color.RESET}")
                country = detected

        # Fetch from publicdns.info
        limit = None if args.all else args.top * 5  # Fetch extra, we'll trim after adding well-known
        fetched = fetch_resolvers(country=country, dnssec_only=args.privacy, limit=limit)
        print(f"{Color.DIM}Found {len(fetched)} resolvers{' in ' + country.upper() if country else ''}{Color.RESET}")

        # Always include well-known resolvers at the start
        well_known_list = [
            {"ip": ip, "name": name, "country": "GLOBAL", "org": name, "dnssec": True, "reliability": 1.0}
            for ip, name in WELL_KNOWN.items()
            if ":" not in ip  # IPv4 only
        ]

        # Merge: well-known first, then fetched (dedup)
        seen_ips = set()
        for r in well_known_list:
            if r["ip"] not in seen_ips:
                resolvers.append(r)
                seen_ips.add(r["ip"])

        for r in fetched:
            if r["ip"] not in seen_ips:
                resolvers.append(r)
                seen_ips.add(r["ip"])

        # Trim to requested count
        if not args.all:
            resolvers = resolvers[:args.top]

    if not resolvers:
        print(f"{Color.RED}No resolvers found. Try without --country filter.{Color.RESET}")
        sys.exit(1)

    # Select test domains
    domains = TEST_DOMAINS[:5] if args.gaming else TEST_DOMAINS[:3]
    total = len(resolvers)

    print(f"\n{Color.BOLD}Testing {total} resolvers ({args.rounds} rounds, {len(domains)} domains each)...{Color.RESET}\n")

    # Run benchmarks in parallel
    results = []
    completed = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for r in resolvers:
            future = executor.submit(benchmark_server, r["ip"], domains, args.rounds, args.timeout)
            futures[future] = r

        for future in as_completed(futures):
            r_info = futures[future]
            result = future.result()
            result["org"] = r_info.get("org", "")
            result["country"] = r_info.get("country", "")
            result["dnssec"] = r_info.get("dnssec", False)
            result["display_name"] = WELL_KNOWN.get(result["server"], r_info.get("org", ""))
            results.append(result)

            completed += 1
            if not args.quiet:
                status = f"{Color.GREEN}✓{Color.RESET}" if result["status"] != "TIMEOUT" else f"{Color.RED}✗{Color.RESET}"
                pct = completed * 100 // total
                sys.stdout.write(f"\r  {status} [{pct:3d}%] {completed}/{total} tested")
                sys.stdout.flush()

    if not args.quiet:
        print("\n")

    # Display results
    if args.quiet:
        working = sorted([r for r in results if r["status"] != "TIMEOUT"], key=lambda x: x["avg_ms"])
        for r in working[:5]:
            name = WELL_KNOWN.get(r["server"], r.get("org", ""))
            print(f"{r['server']}\t{r['avg_ms']:.1f}ms\t{name}")
    else:
        print_results(results, gaming_mode=args.gaming)

    # Export if requested
    if args.export:
        export_results(results, args.export, args.gaming)


if __name__ == "__main__":
    main()
