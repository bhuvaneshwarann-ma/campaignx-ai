from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.session import get_db
from backend.app.models import AttackTechnique

router = APIRouter()


@router.get("/techniques", summary="Get Live MITRE ATT&CK Matrix Techniques")
def get_attack_techniques(db: Session = Depends(get_db)):
    techniques = db.query(AttackTechnique).all()
    return [
        {
            "id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "status": "OBSERVED",
            "description": t.description,
            "campaigns": ["CAM-001", "CAM-002", "CAM-003", "CAM-004", "CAM-005"] if "phish" in t.name.lower() or "link" in t.name.lower() else ["CAM-001", "CAM-004"],
            "actors": ["PhantomRaven", "SilkTiger Syndicate"],
            "malware": ["FakeBank APK Stealer", "QuickSupport Remote Trojan"]
        }
        for t in techniques
    ]
