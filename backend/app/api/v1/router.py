from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    health, auth, incidents, ioc, campaigns, hunting, ai, evaluation, dashboard, reports, graph, attack, feed
)

api_router = APIRouter()

# Core Services
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(dashboard.router, prefix="/stats", tags=["Dashboard"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(ioc.router, prefix="/ioc", tags=["IOC Intelligence"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Campaigns"])
api_router.include_router(hunting.router, prefix="/hunting", tags=["Threat Hunting"])
api_router.include_router(graph.router, prefix="/graph", tags=["Threat Graph"])
api_router.include_router(attack.router, prefix="/attack", tags=["MITRE ATT&CK"])
api_router.include_router(ai.router, prefix="/ai", tags=["AI Investigator"])
api_router.include_router(evaluation.router, prefix="/evaluation", tags=["Evaluation Engine"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reporting"])
api_router.include_router(feed.router, prefix="/feed", tags=["Real-Time Threat Feeds"])

