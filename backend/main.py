import asyncio
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import stripe
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from analyzer import AnalyzerError, analyze_scan_data, generate_report_content, merge_scan_and_analysis
from report_generator import build_pdf_report
from scanner import DOMAIN_PATTERN, ScannerError, scan_domain

# Load environment variables0
load_dotenv(Path(__file__).resolve().parent / ".env")

# Initialize single FastAPI instance
app = FastAPI(title="SentinelScout API")

# Add CORS Middleware ONCE
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


class CheckoutRequest(BaseModel):
    price_id: str = Field(..., pattern=r"^price_[A-Za-z0-9_]+$")
    domain: str = Field(..., examples=["example.com"])
    user_email: str | None = None


def get_stripe_secret_key() -> str:
    secret_key = os.environ.get("STRIPE_SECRET_KEY")
    if not secret_key:
        raise HTTPException(
            status_code=500,
            detail="Stripe is not configured. Set STRIPE_SECRET_KEY.",
        )
    return secret_key


def get_stripe_value(obj: Any, key: str, default: Any = None) -> Any:
    try:
        return obj[key]
    except (KeyError, TypeError):
        return default


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


def run_report_pipeline(domain: str) -> tuple[bytes, str]:
    scan_data = run_scan_pipeline(domain)
    report_content = generate_report_content(domain, scan_data["subdomains"])
    generated_at = datetime.now()
    pdf_bytes = build_pdf_report(domain, scan_data, report_content, generated_at)
    date_stamp = generated_at.strftime("%Y-%m-%d")
    filename = f"sentinel-scout-{domain}-{date_stamp}.pdf"
    return pdf_bytes, filename


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


@app.post("/report")
async def generate_report(payload: ScanRequest, request: Request):
    domain = validate_domain(payload.domain)
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    try:
        pdf_bytes, filename = await asyncio.wait_for(
            asyncio.to_thread(run_report_pipeline, domain),
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=408,
            detail="Report generation timed out after 5 minutes.",
        ) from exc
    except ScannerError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except AnalyzerError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {exc}",
        ) from exc


@app.post("/create-checkout-session")
async def create_checkout_session(payload: CheckoutRequest):
    domain = validate_domain(payload.domain)
    secret_key = get_stripe_secret_key()

    try:
        session = await asyncio.to_thread(
            stripe.checkout.Session.create,
            api_key=secret_key,
            mode="payment",
            line_items=[{"price": payload.price_id, "quantity": 1}],
            success_url=(
                "http://localhost:3000/success"
                "?session_id={CHECKOUT_SESSION_ID}"
            ),
            cancel_url="http://localhost:3000/cancel",
            customer_email=payload.user_email,
            metadata={
                "domain": domain,
                "user_email": payload.user_email or "pending_checkout",
            },
        )
    except stripe.StripeError as exc:
        message = getattr(exc, "user_message", None) or str(exc)
        raise HTTPException(
            status_code=502,
            detail=f"Unable to create Stripe Checkout session: {message}",
        ) from exc

    if not session.url:
        raise HTTPException(
            status_code=502,
            detail="Stripe did not return a Checkout URL.",
        )

    return {"url": session.url}


@app.post("/webhook")
async def stripe_webhook(request: Request):
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail="Stripe webhook is not configured. Set STRIPE_WEBHOOK_SECRET.",
        )

    payload = await request.body()
    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header.")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            signature,
            webhook_secret,
        )
    except (ValueError, stripe.SignatureVerificationError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid Stripe webhook payload or signature.",
        ) from exc

    event_data = (
        event.to_dict_recursive()
        if hasattr(event, "to_dict_recursive")
        else event
    )

    if event_data["type"] == "checkout.session.completed":
        session = event_data["data"]["object"]
        metadata = get_stripe_value(session, "metadata", {}) or {}
        customer_details = get_stripe_value(session, "customer_details", {}) or {}
        domain = get_stripe_value(metadata, "domain", "unknown domain")
        customer_email = (
            get_stripe_value(customer_details, "email")
            or get_stripe_value(session, "customer_email")
            or get_stripe_value(metadata, "user_email")
            or "unknown customer"
        )
        print(f"Payment received for {domain} by {customer_email}", flush=True)

    return {"received": True}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
