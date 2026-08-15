#!/usr/bin/env python3
"""Queries VirusTotal API v3 for IP reputation data.

Usage:
    python virustotal_check.py <ip> [<ip> ...] [--mock-dir DIR]

Requires VT_API_KEY set in the environment (via .env — see .env.example).
--mock-dir reads cached JSON responses instead of calling the live API; see
sample_data/virustotal_mock/ and the assignment's "External API fallback"
instructions for when to use this (no key, quota exhausted, no network).
"""
import argparse
import datetime
import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"


def check_ip(ip: str, api_key: str | None, mock_dir: str | None) -> dict:
    if mock_dir:
        try:
            with open(f"{mock_dir}/{ip}.json") as f:
                payload = json.load(f)
        except FileNotFoundError:
            return {"error": f"no mock file for {ip} in {mock_dir}"}
        except json.JSONDecodeError as e:
            return {"error": f"invalid mock JSON: {e}"}
    else:
        if not api_key:
            return {"error": "VT_API_KEY is not set — add it to .env or export it"}
        try:
            resp = requests.get(
                f"{VT_BASE_URL}{ip}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code == 404:
                return {"error": f"{ip} not found in VirusTotal"}
            if resp.status_code == 401:
                return {"error": "invalid VT_API_KEY"}
            if resp.status_code == 429:
                return {"error": "VirusTotal rate limit hit — try again later"}
            resp.raise_for_status()
            payload = resp.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"request failed: {e}"}
        except json.JSONDecodeError as e:
            return {"error": f"invalid JSON response: {e}"}

    try:
        attrs = payload["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        ts = attrs.get("last_analysis_date")
        last_analysis_date = (
            datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
            if ts is not None else "unknown"
        )
        return {
            "malicious": stats.get("malicious", 0),
            "harmless": stats.get("harmless", 0),
            "last_analysis_date": last_analysis_date,
        }
    except KeyError as e:
        return {"error": f"unexpected response shape, missing key {e}"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check IP reputation via VirusTotal API v3")
    parser.add_argument("ips", nargs="+", help="One or more IPv4 addresses to check")
    parser.add_argument("--mock-dir", help="Read cached JSON responses instead of calling the live API")
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    results = {ip: check_ip(ip, api_key, args.mock_dir) for ip in args.ips}
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
