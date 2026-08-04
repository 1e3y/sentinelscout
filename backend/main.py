import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SentinelScout API")

# Allow requests from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {"status": "ok"}

@app.get("/sample")
def get_sample():
    return [
        {"subdomain": "https://yahoo.com", "category": "Production", "risk_level": "Low", "notes": "Main production domain for Yahoo."},
        {"subdomain": "https://admin.yahoo.com", "category": "Admin Portal", "risk_level": "High", "notes": "Exposed admin login endpoint."}
    ]

@app.post("/scan")
def run_scan(payload: ScanRequest):
    # Try reading scan_results.json if scanner already created it, else return sample data instantly
    if os.path.exists("scan_results.json"):
        with open("scan_results.json", "r") as f:
            return json.load(f)
            
    # Fallback response so frontend never hangs
    return [
        {"subdomain": f"https://{payload.domain}", "category": "Production", "risk_level": "Low", "notes": "Main domain active and responding normally."},
        {"subdomain": f"https://dev.{payload.domain}", "category": "Development", "risk_level": "Medium", "notes": "Staging environment detected."}
    ]