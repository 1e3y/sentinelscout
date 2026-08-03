#!/usr/bin/env python3
"""Probe subdomains with httpx and save scan results."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SCAN_RESULTS_PATH = SCRIPT_DIR / "scan_results.json"


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


def run_httpx(targets: list[str]) -> list[dict]:
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
    except FileNotFoundError:
        print("Error: httpx is not installed or not on PATH.", file=sys.stderr)
        sys.exit(1)

    if process.returncode not in (0, 1):
        print(f"Error: httpx failed: {process.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

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


def save_scan_results(results: list[dict]) -> None:
    try:
        with SCAN_RESULTS_PATH.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
            f.write("\n")
    except OSError as exc:
        print(f"Error: Could not write {SCAN_RESULTS_PATH.name}: {exc}", file=sys.stderr)
        sys.exit(1)


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

    targets = load_targets(args)
    results = run_httpx(targets)
    save_scan_results(results)
    print_results_table(results)


if __name__ == "__main__":
    main()
