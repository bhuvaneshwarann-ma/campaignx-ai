from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from backend.app.services.live_feed_service import live_feed_service
from backend.app.providers.manager import provider_manager
from backend.app.core.config import settings

router = APIRouter()


@router.post("/sync", summary="Trigger Real-Time Threat Feed Sync")
async def sync_live_feeds(
    limit: int = Query(20, ge=5, le=50),
):
    """
    Fetches real-time cyber threats from live online feeds (URLhaus, ThreatFox),
    extracts Scam DNA, resolves canonical entities, and clusters into active campaigns.
    """
    result = await live_feed_service.sync_live_feeds(max_items=limit)
    return result


@router.get("/status", summary="Get Live Threat Feed Connectors Status")
def get_feed_status():
    """
    Returns health and connection status of real-time feed connectors.
    """
    return {
        "mode": settings.MODE,
        "is_offline": settings.is_offline,
        "connectors": {
            "URLhaus": "ACTIVE (abuse.ch Live Feed)",
            "ThreatFox": "ACTIVE (abuse.ch IOC Telemetry)",
            "Live DNS (DoH)": "ACTIVE (Cloudflare 1.1.1.1)",
            "Live GeoIP": "ACTIVE (IP-API Live)",
            "CIRCL CVE / NVD": "ACTIVE (CIRCL.lu Live)"
        },
        "providers_health": provider_manager.get_provider_health(),
        "stream_events_in_buffer": len(live_feed_service.get_live_stream(100))
    }


@router.get("/stream", summary="Get Live Threat Telemetry Stream")
def get_live_stream(limit: int = Query(20, ge=1, le=50)):
    """
    Streams recent real-time ingested threat events for SOC dashboards.
    """
    events = live_feed_service.get_live_stream(limit=limit)
    return {
        "total": len(events),
        "events": events
    }
