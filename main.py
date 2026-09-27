import os
import io
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from PIL import Image

from backend.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HistoryItem,
    ModelMetricsResponse
)
from backend.risk_engine import calculate_risk
from backend.classifier import get_model_metrics, get_or_load_pipeline
from backend.database import (
    init_db,
    save_scan,
    get_recent_history,
    get_scan_detail,
    delete_scan,
    clear_all_history,
    get_stats
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="AI Scam Detector for Messages & Websites",
    description="Cybersecurity intelligence system for detecting phishing, scams, and malicious URLs.",
    version="1.0.0"
)

# Initialize database immediately on module load
init_db()

# Enable CORS for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# Analysis Endpoints
# -------------------------------------------------------------
@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_input(payload: AnalyzeRequest):
    text = payload.text or ""
    url = payload.url or ""
    input_type = payload.input_type or "message"

    if not text.strip() and not url.strip():
        raise HTTPException(status_code=400, detail="Either message text or website URL must be provided.")

    # Calculate multi-signal risk
    analysis = calculate_risk(text=text, raw_url=url, input_type=input_type)

    raw_input_content = text if text.strip() else url
    snippet = raw_input_content[:120]

    # Save to history database
    record_id = save_scan(
        input_type=input_type,
        raw_input=raw_input_content,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        primary_category=analysis["primary_category"],
        is_scam=analysis["is_scam"],
        ml_probability=analysis["ml_scam_probability"],
        indicators=[ind.dict() for ind in analysis["detected_indicators"]],
        url_analysis=analysis["url_analysis"].dict() if analysis["url_analysis"] else None,
        recommendations=analysis["safety_recommendations"]
    )

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return AnalyzeResponse(
        id=record_id,
        input_type=input_type,
        input_snippet=snippet,
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        primary_category=analysis["primary_category"],
        is_scam=analysis["is_scam"],
        ml_scam_probability=analysis["ml_scam_probability"],
        ml_confidence_label=analysis["ml_confidence_label"],
        detected_indicators=analysis["detected_indicators"],
        url_analysis=analysis["url_analysis"],
        safety_recommendations=analysis["safety_recommendations"],
        summary_explanation=analysis["summary_explanation"],
        viva_summary=analysis["viva_summary"],
        created_at=now_str
    )

# -------------------------------------------------------------
# Server-side OCR & File Processing
# -------------------------------------------------------------
@app.post("/api/ocr")
async def process_ocr_upload(file: UploadFile = File(...)):
    """Accepts uploaded screenshot and attempts text extraction."""
    try:
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
        # Optional: check if pytesseract is available
        extracted_text = ""
        try:
            import pytesseract
            extracted_text = pytesseract.image_to_string(image)
        except Exception:
            # When system tesseract binary is not installed, provide clean notice;
            # frontend Tesseract.js WebAssembly provides instant client-side OCR!
            extracted_text = ""

        return {
            "filename": file.filename,
            "width": image.width,
            "height": image.height,
            "extracted_text": extracted_text.strip(),
            "server_ocr_available": bool(extracted_text)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process image: {str(e)}")

# -------------------------------------------------------------
# History & Statistics Endpoints
# -------------------------------------------------------------
@app.get("/api/history", response_model=List[HistoryItem])
async def list_history(limit: int = 50):
    return get_recent_history(limit=limit)

@app.get("/api/history/{scan_id}")
async def get_history_detail(scan_id: int):
    record = get_scan_detail(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record

@app.delete("/api/history/{scan_id}")
async def remove_history_item(scan_id: int):
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found.")
    return {"message": "Scan deleted successfully"}

@app.delete("/api/history")
async def clear_history():
    clear_all_history()
    return {"message": "All scan history cleared"}

@app.get("/api/stats")
async def get_dashboard_stats():
    return get_stats()

@app.get("/api/metrics", response_model=ModelMetricsResponse)
async def get_metrics():
    return get_model_metrics()

# -------------------------------------------------------------
# Preset Samples for Viva & Demonstration
# -------------------------------------------------------------
@app.get("/api/presets")
async def get_presets():
    return [
        {
            "id": "preset_prize",
            "title": "Prize / Lottery Scam (KBC / Lucky Draw)",
            "type": "message",
            "category": "Prize Scam",
            "content": "Congratulations! You have won Rs 25,00,000 in the National Lucky Draw. Pay Rs 999 processing fee immediately to claim your prize. Click: http://claim-prize-example.xyz"
        },
        {
            "id": "preset_bank",
            "title": "Bank KYC Phishing (Urgent Threat)",
            "type": "message",
            "category": "Phishing",
            "content": "URGENT! Your SBI account has been suspended due to incomplete KYC. Update your PAN and Aadhaar immediately at http://sbi-kyc-verify-portal.xyz to avoid permanent blockage."
        },
        {
            "id": "preset_delivery",
            "title": "Fake Courier Delivery Fee (FedEx)",
            "type": "message",
            "category": "Delivery Scam",
            "content": "FedEx: Your package #FD-8921 is held at customs due to an incomplete delivery address. Pay Rs 85 redelivery fee to dispatch today: http://fedx-deliver-status.xyz/pay"
        },
        {
            "id": "preset_job",
            "title": "Work From Home / Telegram Task Scam",
            "type": "message",
            "category": "Job Scam",
            "content": "Part-time job opportunity! Earn Rs 3,000 to Rs 8,000 daily from home by liking YouTube videos and rating hotels on Google Maps. No experience needed. Contact HR manager on Telegram @EarnDailyJobs."
        },
        {
            "id": "preset_financial",
            "title": "Electricity Bill Threat / Extortion",
            "type": "message",
            "category": "Financial Scam",
            "content": "Dear customer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Immediately call electricity officer at 9812345678."
        },
        {
            "id": "preset_legit_otp",
            "title": "Legitimate Bank OTP (Authentic Alert)",
            "type": "message",
            "category": "Legitimate",
            "content": "Your OTP for login to HDFC NetBanking is 591823. Valid for 10 minutes. Do not share your OTP, NetBanking password, or CVV with anyone including bank staff."
        },
        {
            "id": "preset_legit_txn",
            "title": "Legitimate Bank Debit Alert (Normal Alert)",
            "type": "message",
            "category": "Legitimate",
            "content": "Dear Customer, Rs 1,500.00 debited from your A/c XX4892 on 24-Sep-24 towards Amazon Retail. Available balance: Rs 42,310.50. Call 1800112211 if not done by you. - SBI"
        },
        {
            "id": "preset_phish_url",
            "title": "Malicious Typosquatting Website URL",
            "type": "url",
            "category": "Phishing",
            "content": "http://192.168.1.105/sbi-netbanking-secure-login.xyz/verify?user=admin"
        },
        {
            "id": "preset_safe_url",
            "title": "Legitimate Government / Secure Website",
            "type": "url",
            "category": "Legitimate",
            "content": "https://www.incometax.gov.in"
        }
    ]

# -------------------------------------------------------------
# Static Frontend Serving
# -------------------------------------------------------------
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=str(FRONTEND_DIR / "css")), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=str(FRONTEND_DIR / "js")), name="js")

    @app.get("/")
    async def serve_index():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/docs.html")
    async def serve_docs_html():
        return FileResponse(str(FRONTEND_DIR / "docs.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
