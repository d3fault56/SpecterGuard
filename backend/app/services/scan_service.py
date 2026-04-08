"""
Scan Service - MINIMAL VERSION FOR SPEED TEST
Just returns instant hardcoded result to test the system works.
"""

from sqlalchemy.orm import Session
from app.models import ScanRequest, ScanResponse
from app.database import ScanRecord
from typing import List
import json


class ScanService:
    """Minimal service - instant response."""
    
    def __init__(self):
        pass
    
    def scan(self, request: ScanRequest, db: Session) -> ScanResponse:
        """Return instant result for testing."""
        
        # Detect if likely scam based on simple keywords
        content_lower = request.content.lower()
        
        is_scam = any([
            'verify' in content_lower and 'account' in content_lower,
            'password' in content_lower,
            'confirm' in content_lower and 'identity' in content_lower,
            'click here' in content_lower and 'immediately' in content_lower,
        ])
        
        if is_scam:
            verdict = "likely_scam"
            confidence = 0.85
            explanation = "Contains common phishing phrases"
            red_flags = ["Urgency language", "Account verification request"]
        else:
            verdict = "safe"
            confidence = 0.1
            explanation = "No obvious scam indicators detected"
            red_flags = []
        
        # Store in database
        record = ScanRecord(
            input_type=request.input_type,
            input_content=request.content,
            verdict=verdict,
            confidence=confidence,
            explanation=explanation,
            red_flags=json.dumps(red_flags),
            analyzer_used="minimal-test",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        
        return ScanResponse(
            id=record.id,
            verdict=verdict,
            confidence=confidence,
            explanation=explanation,
            red_flags=red_flags,
            analyzer_used="minimal-test",
            created_at=record.created_at,
        )
    
    def get_history(self, db: Session, limit: int = 50) -> tuple[List[ScanResponse], int]:
        """Fetch scan history."""
        
        records = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit).all()
        total = db.query(ScanRecord).count()
        
        responses = [
            ScanResponse(
                id=r.id,
                verdict=r.verdict,
                confidence=r.confidence,
                explanation=r.explanation,
                red_flags=json.loads(r.red_flags) if r.red_flags else [],
                analyzer_used=r.analyzer_used,
                created_at=r.created_at,
            )
            for r in records
        ]
        
        return responses, total