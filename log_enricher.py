#!/usr/bin/env python3
"""Extracts public IPv4 addresses from a log file and enriches each via ip-api.com.

Usage:
    python log_enricher.py <log_file> [--mock-dir DIR]

--mock-dir reads cached JSON responses from disk instead of calling the live
API — see sample_data/ip_api_mock/ and the assignment's own "External API
fallback" instructions for when/why to use this.
"""
import argparse
import ipaddress
import json
import re

import requests

# Matches four dot-separated groups of 1-3 digits. This intentionally also
# matches some invalid addresses (e.g. 999.999.999.999) — ipaddress.ip_address()
# below is what actually validates and classifies each candidate.
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Exactly the three ranges the assignment specifies — deliberately NOT using
# ipaddress.ip_address().is_private, which also excludes loopback, link-local,
# and RFC 5737 documentation/TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24). That broader definition would wrongly skip a real public
# attacker IP like 203.0.113.5 (used throughout this project's Q3 scenario),
# which the task only asks to skip 10.x.x.x / 172.16-31.x.x / 192.168.x.x.
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_excluded_private(ip_obj: ipaddress.IPv4Address) -> bool:
    return any(ip_obj in net for net in PRIVATE_RANGES)


def extract_public_ips(log_path: str) -> set[str]:
    public_ips: set[str] = set()
    with open(log_path, "r", errors="replace") as f:
        for line in f:
            for candidate in IPV4_PATTERN.findall(line):
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                except ValueError:
                    continue  # matched the dotted-decimal shape but isn't a real IPv4 (e.g. an octet > 255)
                if not is_excluded_private(ip_obj):
                    public_ips.add(candidate)
    return public_ips


def enrich_ip(ip: str, session: requests.Session, mock_dir: str | None) -> dict:
    if mock_dir:
        try:
            with open(f"{mock_dir}/{ip}.json") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {"error": f"no mock file for {ip} in {mock_dir}"}
        except json.JSONDecodeError as e:
            return {"error": f"invalid mock JSON: {e}"}
    else:
        try:
            resp = session.get(f"http://ip-api.com/json/{ip}", timeout=5)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"request failed: {e}"}
        except json.JSONDecodeError as e:
            return {"error": f"invalid JSON response: {e}"}

    if data.get("status") == "fail":
        return {"error": data.get("message", "ip-api.com returned a failure status")}

    return {
        "country": data.get("country", "unknown"),
        "isp": data.get("isp", "unknown"),
        "hosting": data.get("hosting", False),
        "proxy": data.get("proxy", False),
        "mobile": data.get("mobile", False),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and enrich public IPs from a log file")
    parser.add_argument("log_file", help="Path to a syslog/firewall log file")
    parser.add_argument("--mock-dir", help="Read cached JSON responses from this directory instead of calling the live API")
    args = parser.parse_args()

    public_ips = extract_public_ips(args.log_file)
    session = requests.Session()

    enriched = {ip: enrich_ip(ip, session, args.mock_dir) for ip in sorted(public_ips)}
    print(json.dumps(enriched, indent=2))


if __name__ == "__main__":
    main()
