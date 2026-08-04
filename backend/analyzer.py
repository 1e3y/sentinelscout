#!/usr/bin/env python3
"""Analyze subdomain scan results using an OpenAI-compatible API."""

import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import APIConnectionError, APIError, AuthenticationError, OpenAI, RateLimitError

load_dotenv()

SCRIPT_DIR = Path(__file__).resolve().parent
SCAN_RESULTS_PATH = SCRIPT_DIR / "scan_results.json"
SAMPLE_SCAN_PATH = SCRIPT_DIR.parent / "sample_data" / "sample_scan.json"
ENV_PATH = SCRIPT_DIR / ".env"
MODEL = "deepseek-chat"

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Analyze the following subdomain scan results. "
    "For each subdomain, categorize it as: Admin Panel, Production, Staging, Development, "
    "CDN, or Unknown. Flag any subdomains that look high-risk or exposed. Return ONLY valid "
    "JSON with this structure: {\"subdomains\": [{\"subdomain\": \"url\", \"category\": \"type\", "
    "\"risk_level\": \"Low/Medium/High\", \"notes\": \"explanation\"}], "
    "\"summary\": \"Brief overall assessment of the scan findings and key risks\"}"
)


class AnalyzerError(Exception):
    """Raised when AI analysis fails."""


def load_scan_results() -> dict | list:
    if SCAN_RESULTS_PATH.exists():
        path = SCAN_RESULTS_PATH
    elif SAMPLE_SCAN_PATH.exists():
        path = SAMPLE_SCAN_PATH
    else:
        raise AnalyzerError(
            f"Neither {SCAN_RESULTS_PATH.name} nor {SAMPLE_SCAN_PATH} found."
        )

    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise AnalyzerError(f"Invalid JSON in {path.name}: {exc}") from exc
    except OSError as exc:
        raise AnalyzerError(f"Could not read {path.name}: {exc}") from exc


def get_openai_client() -> OpenAI:
    load_dotenv(ENV_PATH)
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")

    if not api_key:
        raise AnalyzerError(
            "OPENAI_API_KEY not found. Set it in .env in the same folder as analyzer.py."
        )

    if not base_url:
        raise AnalyzerError(
            "OPENAI_BASE_URL not found. Set it in .env in the same folder as analyzer.py."
        )

    return OpenAI(api_key=api_key, base_url=base_url)


def extract_json_from_response(content: str) -> dict:
    content = content.strip()

    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content, re.IGNORECASE)
    if fence_match:
        content = fence_match.group(1).strip()

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise AnalyzerError(f"AI response is not valid JSON: {exc}") from exc

    if isinstance(parsed, list):
        return {"subdomains": parsed, "summary": ""}

    if not isinstance(parsed, dict):
        raise AnalyzerError("AI response must be a JSON object or array.")

    parsed.setdefault("subdomains", [])
    parsed.setdefault("summary", "")
    return parsed


def analyze_scan_data(scan_data: list[dict]) -> dict:
    client = get_openai_client()

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(scan_data, indent=2)},
            ],
            temperature=0.2,
        )
    except AuthenticationError as exc:
        raise AnalyzerError("Authentication failed. Check your OPENAI_API_KEY.") from exc
    except RateLimitError as exc:
        raise AnalyzerError("Rate limit exceeded. Try again later.") from exc
    except APIConnectionError as exc:
        raise AnalyzerError(f"Could not connect to API: {exc}") from exc
    except APIError as exc:
        raise AnalyzerError(f"API error: {exc}") from exc

    content = response.choices[0].message.content
    if not content:
        raise AnalyzerError("API returned an empty response.")

    return extract_json_from_response(content)


def merge_scan_and_analysis(
    scan_data: list[dict], analysis: dict
) -> list[dict]:
    analysis_by_url = {
        item.get("subdomain", ""): item for item in analysis.get("subdomains", [])
    }

    merged: list[dict] = []
    for item in scan_data:
        url = item.get("url", "")
        ai_result = analysis_by_url.get(url, {})
        merged.append(
            {
                "url": url,
                "status_code": item.get("status_code"),
                "title": item.get("title", ""),
                "category": ai_result.get("category", "Unknown"),
                "risk_level": ai_result.get("risk_level", "Unknown"),
                "notes": ai_result.get("notes", ""),
            }
        )

    return merged


def print_results_table(results: list[dict]) -> None:
    headers = ["Subdomain", "Category", "Risk Level", "Notes"]
    rows = [
        [
            str(item.get("subdomain", item.get("url", ""))),
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
    try:
        scan_data = load_scan_results()
        analysis = analyze_scan_data(scan_data)
        print_results_table(analysis.get("subdomains", []))
        if analysis.get("summary"):
            print()
            print("Summary:")
            print(analysis["summary"])
    except AnalyzerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
