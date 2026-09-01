from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.core.config import settings

router = APIRouter()


@router.get("/health", summary="Health Check")
async def health_check():
    """Return health status, current mode (offline/online), and service timestamps."""
    return {
        "status": "healthy",
        "app": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mode": settings.MODE,
        "is_offline": settings.is_offline,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "database": "available",
            "correlation_engine": "ready",
            "entity_resolver": "ready",
            "graph_engine": "ready",
            "risk_engine": "ready",
            "ai_investigator": "mock_mode" if settings.is_offline else "live_mode",
        }
    }
