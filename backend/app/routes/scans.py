from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.models import ScanRequest, ScanResponse
from app.database import get_db
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/scans", tags=["scans"])
scan_service = ScanService()

@router.post("", response_model=ScanResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    Run scam detection on user input.
    
    FUTURE:
    - Add authentication (user_id from JWT)
    - Support async processing for large batches
    - Add result streaming for long-running analyses
    - Log telemetry for model performance tracking
    """
    try:
        return scan_service.scan(request, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("", response_model=dict)
def get_history(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve scan history."""
    scans, total = scan_service.get_history(db, limit)
    return {"scans": scans, "total": total}