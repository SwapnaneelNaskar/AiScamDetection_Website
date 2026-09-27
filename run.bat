@echo off
title AI Scam Detector for Messages and Websites
echo ============================================================
echo   AI Scam Detector for Messages and Websites
echo   Real-Time Threat Intelligence & Protection
echo ============================================================
echo.

cd /d "%~dp0"

IF NOT EXIST ".venv\Scripts\python.exe" (
    echo [*] Virtual environment not found. Setting up .venv...
    python -m venv .venv
    echo [*] Installing dependencies from requirements.txt...
    .\.venv\Scripts\pip install -r requirements.txt
)

echo [*] Starting FastAPI Server on http://127.0.0.1:8000 ...
echo [*] Press CTRL+C to terminate.
echo.

start "" "http://127.0.0.1:8000"
.\.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
