from fastapi import APIRouter

router = APIRouter(tags=["health"])

@router.get("/api/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}