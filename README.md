# dns-toolkit

**Cross-platform DNS tools powered by [publicdns.info](https://publicdns.info) — the largest live-tested public DNS directory (8,500+ resolvers across 193 countries).**

Zero-dependency Python scripts for benchmarking, monitoring, and optimizing your DNS configuration. Data sourced from publicdns.info's continuously monitored resolver database.

## Tools

### dns_bench.py — DNS Benchmark

Find the fastest DNS resolver for **your** location. Unlike web-based tests, this runs from your actual machine.

```bash
python3 dns_bench.py                    # Quick benchmark (top 20 resolvers)
python3 dns_bench.py --country US       # Test US resolvers only
python3 dns_bench.py --gaming           # Gaming mode (latency + jitter focus)
python3 dns_bench.py --privacy          # Only DNSSEC-enabled resolvers
python3 dns_bench.py --export results.json  # Export to JSON/CSV
```

**Sample output:**
```
  #  Server             Name                      Avg     Jitter    Rel  Status
  1  9.9.9.9            Quad9                   3.3ms    0.5ms   100% OK
  2  1.1.1.1            Cloudflare              4.6ms    0.6ms   100% OK
  3  8.8.8.8            Google Public DNS       5.6ms    4.5ms   100% OK

★ Fastest: 9.9.9.9 (Quad9) — 3.3ms avg, 0.5ms jitter
```

**How it works:** Fetches the live resolver list from [publicdns.info/nameservers.csv](https://publicdns.info/nameservers.csv), filters by country/features, then benchmarks each one from your network with real DNS queries.

### dns_health.py — DNS Health Monitor

Monitors your DNS resolvers and finds fast alternatives from [publicdns.info](https://publicdns.info) when they degrade.

```bash
python3 dns_health.py check             # One-time health check
python3 dns_health.py monitor           # Continuous monitoring
python3 dns_health.py find-best         # Find optimal DNS for your location
python3 dns_health.py pihole-update     # Optimize Pi-hole upstream DNS
```

**Sample output:**
```
  ✓ HEALTHY  1.1.1.1
         Latency: 4.2ms | Jitter: 0.6ms | Reliability: 100%

  ✗ DOWN     192.168.1.1
         No response — resolver is unreachable

Finding alternatives from publicdns.info...
  Alternative: 9.9.9.9 (Quad9) - 3ms
```

## Features

| Feature | dns_bench | dns_health |
|---------|:---------:|:----------:|
| Pulls live data from [publicdns.info](https://publicdns.info) | ✓ | ✓ |
| Tests from YOUR location | ✓ | ✓ |
| Auto-detects country | ✓ | ✓ |
| Gaming mode (latency + jitter) | ✓ | |
| DNSSEC/privacy filter | ✓ | |
| JSON/CSV export | ✓ | |
| Continuous monitoring | | ✓ |
| Auto-failover suggestions | | ✓ |
| Pi-hole upstream optimizer | | ✓ |
| System DNS detection | | ✓ |
| Event logging | | ✓ |

## Requirements

- Python 3.6+
- - No pip install needed — zero external dependencies
  - - Works on Linux, macOS, Windows, Raspberry Pi
   
    - ## Data Source
   
    - All resolver data comes from [publicdns.info](https://publicdns.info):
   
    - - **8,500+ live-tested** public DNS resolvers
      - - **193 countries** covered
        - - **Tested every 72 hours** for reliability, DNSSEC, and NXDOMAIN integrity
          - - **90,000+ total resolvers** probed continuously
           
            - ### publicdns.info Tools
           
            - | Tool | URL | Description |
            - |------|-----|-------------|
            - | DNS Speed Test | [publicdns.info/dns-gaming-benchmark.html](https://publicdns.info/dns-gaming-benchmark.html) | Web-based DNS speed test |
            - | DNS Privacy Check | [publicdns.info/dns-privacy-check.html](https://publicdns.info/dns-privacy-check.html) | Check DNS privacy grade (A+ to F) |
            - | DNS Dig Lookup | [publicdns.info/dig.html](https://publicdns.info/dig.html) | Online dig tool for any domain |
            - | WHOIS Lookup | [publicdns.info/whois.html](https://publicdns.info/whois.html) | IP and domain WHOIS data |
            - | Resolver Directory | [publicdns.info](https://publicdns.info) | Browse all 8,500+ resolvers |
            - | Gaming DNS | [publicdns.info/best-gaming.html](https://publicdns.info/best-gaming.html) | Best DNS for gaming by country |
            - | Privacy DNS | [publicdns.info/best-privacy.html](https://publicdns.info/best-privacy.html) | Best private DNS providers |
           
            - ## Why This Exists
           
            - | Tool | Platform | Maintained? | Tests from YOUR location? | Live resolver data? |
            - |------|----------|:-----------:|:-------------------------:|:-------------------:|
            - | GRC DNS Benchmark | Windows only | Paid only since 2025 | Yes | No (hardcoded list) |
            - | namebench | Cross-platform | Abandoned 2015 | Yes | No |
            - | dnsperf.com | Web | Yes | No (their servers) | No |
            - | **dns-toolkit** | **Cross-platform** | **Yes** | **Yes** | **Yes (publicdns.info)** |
           
            - ## License
           
            - MIT License — see [LICENSE](LICENSE).
           
            - ## Author
           
            - **Paddraigh O'Sullivan** — IT Consultant, Cork, Ireland
           
            - - GitHub: [@paddraighosullivan-beep](https://github.com/paddraighosullivan-beep)
              - - Data source: [publicdns.info](https://publicdns.info)
               
                - ## Community
               
                - This toolkit was built based on real demand from the DNS and networking community on Reddit. If you're looking for DNS help, these communities are great resources:
               
                - - [r/dns](https://reddit.com/r/dns) — DNS discussions, troubleshooting, and resolver recommendations
                  - - [r/pihole](https://reddit.com/r/pihole) — Pi-hole setup, upstream DNS optimization, ad blocking
                    - - [r/HomeNetworking](https://reddit.com/r/HomeNetworking) — Home network DNS, router configuration
                      - - [r/selfhosted](https://reddit.com/r/selfhosted) — Self-hosted DNS (Unbound, Pi-hole, AdGuard Home)
                        - - [r/sysadmin](https://reddit.com/r/sysadmin) — Enterprise DNS management, DHCP/DDNS, monitoring
                         
                          - ### Discussed on
                         
                          - - [r/dns — "DNS benchmark speed?"](https://old.reddit.com/r/dns/comments/1r684mc/dns_benchmark_speed/) — GRC Benchmark went paid, this fills the gap
                            - - [r/pihole — "Fast DNS server recommendations"](https://old.reddit.com/r/pihole/comments/iakxru/fast_dns_server_recommendations_what_gives_you/) — Finding the fastest upstream DNS for Pi-hole
                              - 
