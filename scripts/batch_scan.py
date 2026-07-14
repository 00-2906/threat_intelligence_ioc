"""
batch_scan.py — Command-line batch IOC scanner.

Reads a list of IOCs from a text file (one per line, format: type,value)
and scans each one against the running IOC Scanner API, saving results
to a CSV file. This is a standalone scripting tool, separate from the
web app — useful for automation (cron jobs, quick bulk checks, CI
pipelines, etc.) without needing to open a browser.

Usage:
    python batch_scan.py --input iocs.txt --output results.csv
    python batch_scan.py --input iocs.txt --output results.csv --api-url http://127.0.0.1:8000

Input file format (iocs.txt), one IOC per line:
    ip,8.8.8.8
    domain,example.com
    hash,44d88612fea8a8f36de82e1278abb02f
    url,http://example.com/suspicious-path
"""
import argparse
import csv
import sys
import time
from pathlib import Path

import requests


def read_iocs(input_path: Path) -> list[tuple[str, str]]:
    """Read IOC lines of the form 'type,value' and skip blanks/comments."""
    iocs = []
    with open(input_path, "r") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 1)
            if len(parts) != 2:
                print(f"[warn] skipping malformed line {line_num}: {raw_line!r}")
                continue
            ioc_type, value = parts[0].strip(), parts[1].strip()
            iocs.append((ioc_type, value))
    return iocs


def scan_one(api_url: str, ioc_type: str, value: str) -> dict:
    """Call the /scan endpoint for a single IOC and pull out the key fields."""
    try:
        resp = requests.post(
            f"{api_url}/scan",
            json={"ioc_type": ioc_type, "value": value},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ioc_type": ioc_type,
            "value": value,
            "status": "ok",
            "errors": "; ".join(data.get("errors", [])),
            "has_virustotal_data": bool(data.get("virustotal")),
            "has_abuseipdb_data": bool(data.get("abuseipdb")),
        }
    except requests.exceptions.RequestException as exc:
        return {
            "ioc_type": ioc_type,
            "value": value,
            "status": "failed",
            "errors": str(exc),
            "has_virustotal_data": False,
            "has_abuseipdb_data": False,
        }


def main():
    parser = argparse.ArgumentParser(description="Batch-scan a list of IOCs via the IOC Scanner API.")
    parser.add_argument("--input", required=True, type=Path, help="Path to input file (type,value per line)")
    parser.add_argument("--output", required=True, type=Path, help="Path to write results CSV")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="Base URL of the running API")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds to wait between requests (avoid rate limits)")
    args = parser.parse_args()

    if not args.input.exists():
        print(f"[error] input file not found: {args.input}")
        sys.exit(1)

    iocs = read_iocs(args.input)
    if not iocs:
        print("[error] no valid IOCs found in input file")
        sys.exit(1)

    print(f"[info] scanning {len(iocs)} IOC(s) against {args.api_url} ...")
    results = []
    for i, (ioc_type, value) in enumerate(iocs, start=1):
        print(f"[{i}/{len(iocs)}] scanning {ioc_type}: {value}")
        results.append(scan_one(args.api_url, ioc_type, value))
        if i < len(iocs):
            time.sleep(args.delay)

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    ok_count = sum(1 for r in results if r["status"] == "ok")
    print(f"[done] {ok_count}/{len(results)} scans succeeded. Results saved to {args.output}")


if __name__ == "__main__":
    main()
