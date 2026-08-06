#!/usr/bin/env python3
"""Probe subdomains with httpx."""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCAN_RESULTS_PATH = SCRIPT_DIR / "scan_results.json"

SUBFINDER_TIMEOUT = 180  # 3 minutes
HTTPX_TIMEOUT = 120  # 2 minutes
MAX_SUBDOMAINS = 500

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class ScannerError(Exception):
    """Raised when subdomain scanning fails."""


@dataclass
class DomainScanResult:
    results: list[dict]
    truncation_note: str | None = None


def sanitize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.match(domain):
        raise ScannerError(
            "Invalid domain. Only alphanumeric characters, hyphens, and dots are allowed."
        )
    if len(domain) > 253:
        raise ScannerError("Domain name too long.")
    return domain


def discover_subdomains(domain: str) -> tuple[list[str], str | None]:
    try:
        process = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=False,
            timeout=SUBFINDER_TIMEOUT,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError("subfinder is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError("subfinder timed out after 3 minutes.") from exc

    if process.returncode not in (0, 1):
        message = process.stderr.strip() or "subfinder exited with an error"
        raise ScannerError(f"subfinder failed: {message}")

    subdomains = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    if not subdomains:
        subdomains = [domain]

    truncation_note = None
    if len(subdomains) > MAX_SUBDOMAINS:
        total_found = len(subdomains)
        subdomains = subdomains[:MAX_SUBDOMAINS]
        truncation_note = (
            f"Subdomain list truncated to {MAX_SUBDOMAINS} of {total_found} discovered."
        )

    return subdomains, truncation_note


def scan_targets(targets: list[str]) -> list[dict]:
    if not targets:
        raise ScannerError("No targets provided for scanning.")

    try:
        process = subprocess.run(
            [
                "httpx",
                "-silent",
                "-json",
                "-title",
                "-status-code",
                "-follow-redirects",
            ],
            input="\n".join(targets),
            capture_output=True,
            text=True,
            check=False,
            timeout=HTTPX_TIMEOUT,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError("httpx is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError("httpx timed out after 2 minutes.") from exc

    if process.returncode not in (0, 1):
        message = process.stderr.strip() or "httpx exited with an error"
        raise ScannerError(f"httpx failed: {message}")

    results: list[dict] = []
    for line in process.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        results.append(
            {
                "url": entry.get("url", ""),
                "status_code": entry.get("status_code"),
                "title": entry.get("title") or "",
            }
        )

    return results


def scan_domain(domain: str) -> DomainScanResult:
    safe_domain = sanitize_domain(domain)
    targets, truncation_note = discover_subdomains(safe_domain)
    results = scan_targets(targets)
    return DomainScanResult(results=results, truncation_note=truncation_note)


def save_scan_results(results: list[dict], path: Path = SCAN_RESULTS_PATH) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        f.write("\n")


def print_results_table(results: list[dict]) -> None:
    headers = ["URL", "Status Code", "Title"]
    rows = [
        [
            str(item.get("url", "")),
            str(item.get("status_code", "")),
            str(item.get("title", "")),
        ]
        for item in results
    ]

    if not rows:
        print("No live subdomains found.")
        return

    col_widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    separator = " | "
    header_line = separator.join(header.ljust(col_widths[i]) for i, header in enumerate(headers))
    divider = "-+-".join("-" * width for width in col_widths)

    print(header_line)
    print(divider)
    for row in rows:
        print(separator.join(row[i].ljust(col_widths[i]) for i in range(len(headers))))


def load_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = []

    if args.file:
        try:
            with args.file.open(encoding="utf-8") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except OSError as exc:
            print(f"Error: Could not read {args.file}: {exc}", file=sys.stderr)
            sys.exit(1)

    targets.extend(args.targets)

    if not targets and not sys.stdin.isatty():
        targets.extend(line.strip() for line in sys.stdin if line.strip())

    if not targets:
        print("Error: Provide targets via arguments, -f/--file, or stdin.", file=sys.stderr)
        sys.exit(1)

    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe subdomains with httpx.")
    parser.add_argument("targets", nargs="*", help="Subdomains or URLs to probe")
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        help="File containing one subdomain or URL per line",
    )
    args = parser.parse_args()

    try:
        targets = load_targets(args)
        results = scan_targets(targets)
        save_scan_results(results)
        print_results_table(results)
    except ScannerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
