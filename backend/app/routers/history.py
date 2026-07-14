from fastapi import APIRouter

from app.db import get_history

router = APIRouter()


@router.get("/history")
def scan_history(limit: int = 50):
    """Your scanner's memory — every IOC it's ever judged, most recent first."""
    return {"scans": get_history(limit)}
