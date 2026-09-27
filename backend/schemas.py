from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AnalyzeRequest(BaseModel):
    text: Optional[str] = Field(default="", description="The suspicious message, email, or extracted OCR text")
    url: Optional[str] = Field(default="", description="Website URL to analyze")
    input_type: str = Field(default="message", description="'message', 'url', or 'screenshot'")

class IndicatorItem(BaseModel):
    name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    score_impact: int
    description: str
    evidence: List[str]

class URLAnalysisResult(BaseModel):
    url: str
    is_valid: bool
    domain: str
    tld: str
    is_ip_address: bool
    is_shortened: bool
    suspicious_tld: bool
    domain_entropy: float
    uses_https: bool
    https_notice: str
    suspicious_keywords: List[str]
    url_risk_score: int
    flags: List[str]

class AnalyzeResponse(BaseModel):
    id: Optional[int] = None
    input_type: str
    input_snippet: str
    risk_score: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    primary_category: str
    is_scam: bool
    ml_scam_probability: float
    ml_confidence_label: str
    detected_indicators: List[IndicatorItem]
    url_analysis: Optional[URLAnalysisResult] = None
    safety_recommendations: List[str]
    summary_explanation: str
    viva_summary: str
    created_at: str

class HistoryItem(BaseModel):
    id: int
    input_type: str
    snippet: str
    risk_score: int
    risk_level: str
    primary_category: str
    indicators_count: int
    created_at: str

class ModelBenchmarkItem(BaseModel):
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float

class ModelMetricsResponse(BaseModel):
    active_model: str
    total_samples: int
    test_split_ratio: float
    benchmark: List[ModelBenchmarkItem]
    confusion_matrix: Dict[str, int]
