from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    url: Optional[str] = Field(default=None, description="Raw URL to evaluate")
    features: Optional[Dict[str, float]] = Field(
        default=None,
        description="Optional feature map matching the trained tabular schema",
    )


class PredictionRecord(BaseModel):
    url: str
    prediction: str
    confidence_score: float
    threat_level: str
    timestamp: datetime
    risk_category: str
    score: float
    source: str = "api"
    reason_codes: List[str] = Field(default_factory=list)
    heuristic_score: float = 0.0
    risk_score: float = 0.0
    decision_threshold: float = 0.52
    triggered_indicators: List[str] = Field(default_factory=list)
    suspicious_keywords: List[str] = Field(default_factory=list)
    brand_hits: List[str] = Field(default_factory=list)
    explanation: str = ""
    risk_score_breakdown: Dict[str, float] = Field(default_factory=dict)
    feature_contribution_breakdown: List[Dict[str, float | str]] = Field(default_factory=list)
    text_evidence: Dict[str, object] = Field(default_factory=dict)


class BatchPredictionSummary(BaseModel):
    total: int
    phishing_count: int
    legitimate_count: int
    average_confidence: float


class BatchPredictionResponse(BaseModel):
    summary: BatchPredictionSummary
    results: List[PredictionRecord]


class ModelInfoResponse(BaseModel):
    model_name: str
    model_path: str
    preprocessor_path: str
    feature_count: int
    trained_artifact_dir: Optional[str] = None
    metrics: Dict[str, float] = Field(default_factory=dict)
    decision_threshold: float = 0.52
    hybrid_detection: bool = True


class ThreatStatsResponse(BaseModel):
    total_predictions: int
    phishing_count: int
    legitimate_count: int
    by_threat_level: Dict[str, int]
    by_risk_category: Dict[str, int]
    recent_predictions: List[PredictionRecord]


class HealthResponse(BaseModel):
    status: str
    environment: str
    model_ready: bool
    history_backend: str
    timestamp: datetime
    uptime_seconds: float
