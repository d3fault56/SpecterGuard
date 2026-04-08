from pydantic import BaseModel, Field
from typing import List
from datetime import datetime

class ScanRequest(BaseModel):
    """User input for analysis."""
    input_type: str = Field(..., description="'text', 'email', or 'url'")
    content: str = Field(..., description="The content to analyze")

class ScanResponse(BaseModel):
    """Analysis result."""
    id: int
    verdict: str  # "likely_scam", "suspicious", "safe"
    confidence: float  # 0.0 to 1.0
    explanation: str
    red_flags: List[str]
    analyzer_used: str
    created_at: datetime

class ScanHistoryResponse(BaseModel):
    """Scan history list."""
    scans: List[ScanResponse]
    total: int