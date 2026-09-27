import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_FILE = Path(__file__).resolve().parent.parent / "scam_detector.db"

def get_connection():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        input_type TEXT NOT NULL,
        raw_input TEXT NOT NULL,
        snippet TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        primary_category TEXT NOT NULL,
        is_scam INTEGER NOT NULL,
        ml_probability REAL NOT NULL,
        indicators_json TEXT NOT NULL,
        url_analysis_json TEXT,
        recommendations_json TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def save_scan(
    input_type: str,
    raw_input: str,
    risk_score: int,
    risk_level: str,
    primary_category: str,
    is_scam: bool,
    ml_probability: float,
    indicators: list,
    url_analysis: Optional[dict],
    recommendations: list
) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    snippet = (raw_input[:100] + "...") if len(raw_input) > 100 else raw_input

    cursor.execute("""
    INSERT INTO scan_history (
        created_at, input_type, raw_input, snippet, risk_score,
        risk_level, primary_category, is_scam, ml_probability,
        indicators_json, url_analysis_json, recommendations_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_str,
        input_type,
        raw_input,
        snippet,
        risk_score,
        risk_level,
        primary_category,
        1 if is_scam else 0,
        float(ml_probability),
        json.dumps(indicators),
        json.dumps(url_analysis) if url_analysis else None,
        json.dumps(recommendations)
    ))
    conn.commit()
    record_id = cursor.lastrowid
    conn.close()
    return record_id

def get_recent_history(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, created_at, input_type, snippet, risk_score, risk_level,
           primary_category, is_scam, indicators_json
    FROM scan_history
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        indicators = json.loads(r["indicators_json"]) if r["indicators_json"] else []
        results.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "input_type": r["input_type"],
            "snippet": r["snippet"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "primary_category": r["primary_category"],
            "indicators_count": len(indicators)
        })
    conn.close()
    return results

def get_scan_detail(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "input_type": row["input_type"],
        "raw_input": row["raw_input"],
        "snippet": row["snippet"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "primary_category": row["primary_category"],
        "is_scam": bool(row["is_scam"]),
        "ml_probability": row["ml_probability"],
        "indicators": json.loads(row["indicators_json"]),
        "url_analysis": json.loads(row["url_analysis_json"]) if row["url_analysis_json"] else None,
        "recommendations": json.loads(row["recommendations_json"])
    }

def delete_scan(scan_id: int) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted

def clear_all_history() -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()
    return True

def get_stats() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM scan_history")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as scams FROM scan_history WHERE is_scam = 1")
    scams = cursor.fetchone()["scams"]

    cursor.execute("SELECT AVG(risk_score) as avg_score FROM scan_history")
    avg_score = cursor.fetchone()["avg_score"] or 0

    cursor.execute("""
    SELECT primary_category, COUNT(*) as count
    FROM scan_history
    GROUP BY primary_category
    ORDER BY count DESC
    """)
    cat_rows = cursor.fetchall()
    categories = {row["primary_category"]: row["count"] for row in cat_rows}

    conn.close()
    return {
        "total_scans": total,
        "scam_detections": scams,
        "safe_messages": total - scams,
        "average_risk_score": round(avg_score, 1),
        "categories_distribution": categories
    }
