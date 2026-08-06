import asyncio
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer import AnalyzerError, analyze_scan_data, merge_scan_and_analysis
from scanner import DOMAIN_PATTERN, ScannerError, scan_domain

app = FastAPI(title="SentinelScout API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SCAN_TIMEOUT_SECONDS = 300  # 5 minutes
RATE_LIMIT_SECONDS = 120  # 2 minutes
rate_limit_store: dict[str, float] = {}


class ScanRequest(BaseModel):
    domain: str = Field(..., examples=["yahoo.com"])


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")

    if not domain:
        raise HTTPException(status_code=422, detail="Domain must not be empty.")

    if not DOMAIN_PATTERN.match(domain):
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid domain. Only alphanumeric characters, hyphens, and dots are allowed. "
                "Special characters, spaces, semicolons, pipes, and backticks are rejected."
            ),
        )

    if len(domain) > 253:
        raise HTTPException(status_code=422, detail="Domain name too long.")

    return domain


def check_rate_limit(client_ip: str) -> None:
    now = time.time()
    last_scan = rate_limit_store.get(client_ip)

    if last_scan is not None and now - last_scan < RATE_LIMIT_SECONDS:
        retry_after = int(RATE_LIMIT_SECONDS - (now - last_scan))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. One scan per IP every 2 minutes. Retry in {retry_after}s.",
        )

    rate_limit_store[client_ip] = now


def run_scan_pipeline(domain: str) -> dict[str, Any]:
    scan_result = scan_domain(domain)
    analysis = analyze_scan_data(scan_result.results)
    subdomains = merge_scan_and_analysis(scan_result.results, analysis)

    summary = analysis.get("summary", "")
    if scan_result.truncation_note:
        summary = (
            f"{scan_result.truncation_note} {summary}".strip()
            if summary
            else scan_result.truncation_note
        )

    response: dict[str, Any] = {
        "domain": domain,
        "subdomains": subdomains,
        "summary": summary,
    }

    if scan_result.truncation_note:
        response["truncation_note"] = scan_result.truncation_note

    return response


@app.get("/")
def read_root():
    return {"status": "ok", "message": "SentinelScout API is running"}


@app.post("/scan")
async def run_scan(payload: ScanRequest, request: Request):
    domain = validate_domain(payload.domain)
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(run_scan_pipeline, domain),
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        return result
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=408,
            detail="Scan timed out after 5 minutes.",
        ) from exc
    except ScannerError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except AnalyzerError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
