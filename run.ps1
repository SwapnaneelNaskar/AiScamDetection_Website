# PowerShell launcher for AI Scam Detector
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AI Scam Detector for Messages and Websites" -ForegroundColor Cyan
Write-Host "  Real-Time Threat Intelligence & Protection" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "[*] Creating virtual environment .venv..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
    .\.venv\Scripts\pip install -r requirements.txt
}

Write-Host "[*] Launching application on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process "http://127.0.0.1:8000"
& .\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
