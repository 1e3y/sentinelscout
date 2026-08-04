#!/usr/bin/env python3
"""Probe subdomains with httpx."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCAN_RESULTS_PATH = SCRIPT_DIR / "scan_results.json"


class ScannerError(Exception):
    """Raised when subdomain scanning fails."""


def discover_subdomains(domain: str) -> list[str]:
    try:
        process = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError("subfinder is not installed or not on PATH.") from exc

    if process.returncode not in (0, 1):
        message = process.stderr.strip() or "subfinder exited with an error"
        raise ScannerError(f"subfinder failed: {message}")

    subdomains = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    return subdomains or [domain]


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
        )
    except FileNotFoundError as exc:
        raise ScannerError("httpx is not installed or not on PATH.") from exc

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


def scan_domain(domain: str) -> list[dict]:
    targets = discover_subdomains(domain)
    return scan_targets(targets)


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
