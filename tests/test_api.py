import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_presets():
    res = client.get("/api/presets")
    assert res.status_code == 200
    presets = res.json()
    assert len(presets) >= 8
    print("[PASS] GET /api/presets loaded successfully with", len(presets), "presets.")

def test_metrics_endpoint():
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "benchmark" in data
    assert len(data["benchmark"]) == 4
    print("[PASS] GET /api/metrics loaded benchmark models.")

def test_analyze_prize_scam():
    payload = {
        "text": "Congratulations! You have won Rs 25,00,000 in lucky draw. Pay Rs 999 fee immediately: http://claim-prize.xyz",
        "input_type": "message"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 80
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert data["primary_category"] == "Prize Scam"
    assert len(data["detected_indicators"]) > 0
    print(f"[PASS] Prize Scam test: Score={data['risk_score']}, Category={data['primary_category']}")

def test_analyze_phishing_scam():
    payload = {
        "text": "URGENT! Your SBI account has been suspended. Update KYC and enter NetBanking password at http://sbi-kyc.xyz immediately.",
        "input_type": "message"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 85
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data["detected_indicators"]) >= 2
    print(f"[PASS] Phishing test: Score={data['risk_score']}, Level={data['risk_level']}")

def test_analyze_legitimate_otp():
    payload = {
        "text": "Your OTP for login to HDFC NetBanking is 591823. Valid for 10 minutes. Do not share OTP with anyone.",
        "input_type": "message"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] <= 35
    assert data["risk_level"] == "LOW"
    assert data["primary_category"] == "Legitimate"
    print(f"[PASS] Legitimate OTP test: Score={data['risk_score']}, Level={data['risk_level']}")

def test_analyze_suspicious_url():
    payload = {
        "url": "http://192.168.1.105/paypal-account-verify.xyz/login",
        "input_type": "url"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["is_ip_address"] is True
    assert data["risk_score"] >= 70
    print(f"[PASS] Malicious URL test: Score={data['risk_score']}, IP Detected={data['url_analysis']['is_ip_address']}")

def test_history_and_stats():
    res = client.get("/api/history")
    assert res.status_code == 200
    history = res.json()
    assert len(history) > 0

    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_scans"] > 0
    print(f"[PASS] History & Stats test: Total scans in SQLite = {stats['total_scans']}")

if __name__ == "__main__":
    test_health_presets()
    test_metrics_endpoint()
    test_analyze_prize_scam()
    test_analyze_phishing_scam()
    test_analyze_legitimate_otp()
    test_analyze_suspicious_url()
    test_history_and_stats()
    print("\n[SUCCESS] ALL AUTOMATED TESTS PASSED CLEANLY!\n")
