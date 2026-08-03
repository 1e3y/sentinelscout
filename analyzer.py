#!/usr/bin/env python3
"""Analyze subdomain scan results using OpenAI."""

import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import APIConnectionError, APIError, AuthenticationError, OpenAI, RateLimitError

SCRIPT_DIR = Path(__file__).resolve().parent
SCAN_RESULTS_PATH = SCRIPT_DIR / "scan_results.json"
ENV_PATH = SCRIPT_DIR / ".env"
MODEL = "deepseek-chat"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Analyze the following subdomain scan results. "
    "For each subdomain, categorize it as: Admin Panel, Production, Staging, Development, "
    "CDN, or Unknown. Flag any subdomains that look high-risk or exposed. Return ONLY valid "
    "JSON with this structure: [{'subdomain': 'url', 'category': 'type', "
    "'risk_level': 'Low/Medium/High', 'notes': 'explanation'}]"
)


def load_scan_results() -> dict | list:
    if not SCAN_RESULTS_PATH.exists():
        print(f"Error: {SCAN_RESULTS_PATH.name} not found in {SCRIPT_DIR}", file=sys.stderr)
        sys.exit(1)

    try:
        with SCAN_RESULTS_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in {SCAN_RESULTS_PATH.name}: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Error: Could not read {SCAN_RESULTS_PATH.name}: {exc}", file=sys.stderr)
        sys.exit(1)


def get_openai_client() -> OpenAI:
    load_dotenv(ENV_PATH)
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")

    if not api_key:
        print(
            "Error: OPENAI_API_KEY not found. Set it in .env in the same folder as analyzer.py.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not base_url:
        print(
            "Error: OPENAI_BASE_URL not found. Set it in .env in the same folder as analyzer.py.",
            file=sys.stderr,
        )
        sys.exit(1)

    return OpenAI(api_key=api_key, base_url=base_url)


def extract_json_from_response(content: str) -> list[dict]:
    content = content.strip()

    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content, re.IGNORECASE)
    if fence_match:
        content = fence_match.group(1).strip()

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AI response is not valid JSON: {exc}") from exc

    if not isinstance(parsed, list):
        raise ValueError("AI response must be a JSON array.")

    return parsed


def analyze_with_openai(client: OpenAI, scan_data: dict | list) -> list[dict]:
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(scan_data, indent=2)},
            ],
            temperature=0.2,
        )
    except AuthenticationError:
        print("Error: OpenAI authentication failed. Check your OPENAI_API_KEY.", file=sys.stderr)
        sys.exit(1)
    except RateLimitError:
        print("Error: OpenAI rate limit exceeded. Try again later.", file=sys.stderr)
        sys.exit(1)
    except APIConnectionError as exc:
        print(f"Error: Could not connect to OpenAI API: {exc}", file=sys.stderr)
        sys.exit(1)
    except APIError as exc:
        print(f"Error: OpenAI API error: {exc}", file=sys.stderr)
        sys.exit(1)

    content = response.choices[0].message.content
    if not content:
        print("Error: OpenAI returned an empty response.", file=sys.stderr)
        sys.exit(1)

    try:
        return extract_json_from_response(content)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def print_results_table(results: list[dict]) -> None:
    headers = ["Subdomain", "Category", "Risk Level", "Notes"]
    rows = [
        [
            str(item.get("subdomain", "")),
            str(item.get("category", "")),
            str(item.get("risk_level", "")),
            str(item.get("notes", "")),
        ]
        for item in results
    ]

    if not rows:
        print("No subdomains to display.")
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
    scan_data = load_scan_results()
    client = get_openai_client()
    results = analyze_with_openai(client, scan_data)
    print_results_table(results)


if __name__ == "__main__":
    main()
