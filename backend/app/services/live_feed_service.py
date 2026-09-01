import httpx
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.database.session import SessionLocal
from backend.app.models import Incident, ScamDNA, Entity, EntityMention, Campaign, ThreatActor, MalwareFamily
from backend.app.services.scam_dna_extractor import extract_scam_dna
from backend.app.services.entity_resolver import extract_and_resolve_entities
from backend.app.services.risk_engine import risk_engine
from backend.app.graph.engine import graph_engine
from backend.app.core.logging import logger

# In-memory circular buffer for real-time telemetry stream
LIVE_STREAM_BUFFER: List[Dict[str, Any]] = []
MAX_STREAM_BUFFER = 100


class LiveFeedService:
    """
    Real-Time Threat Intelligence Feed Ingestor.
    Pulls live active malware, phishing campaigns, C2 infrastructure,
    and attacker indicators from public feeds (URLhaus, ThreatFox).
    """

    async def fetch_urlhaus_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch recent live malware URLs from abuse.ch URLhaus open feed."""
        items = []
        headers = {"User-Agent": "CampaignX-AI-ThreatPlatform/1.0"}
        try:
            async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=10.0) as client:
                res = await client.get("https://urlhaus.abuse.ch/downloads/json_recent/")
                if res.status_code == 200:
                    data = res.json()
                    for key, url_list in data.items():
                        if isinstance(url_list, list):
                            for u in url_list[:limit]:
                                url_val = u.get("url")
                                threat = u.get("threat", "malware_download")
                                tags = u.get("tags") or ["malware"]
                                reporter = u.get("reporter", "abuse.ch")
                                
                                # Extract domain / host from URL
                                host = ""
                                try:
                                    import urllib.parse
                                    host = urllib.parse.urlparse(url_val).hostname or ""
                                except Exception:
                                    pass

                                raw_msg = (
                                    f"[CRITICAL THREAT FEED] Malicious Payload Delivery URL detected: {url_val}\n"
                                    f"Associated Host/Domain: {host}\n"
                                    f"Threat Category: {threat.upper()}\n"
                                    f"Identified Malware Family/Tags: {', '.join(tags) if isinstance(tags, list) else tags}\n"
                                    f"Reported by: {reporter}. Immediate infrastructure blocking recommended."
                                )
                                items.append({
                                    "source": "URLhaus_Live_Feed",
                                    "channel": "malware_delivery",
                                    "language": "english",
                                    "raw_content": raw_msg,
                                    "url": url_val,
                                    "host": host,
                                    "tags": tags if isinstance(tags, list) else [tags],
                                    "threat": threat,
                                    "actor": None,
                                    "malware": tags[0] if (isinstance(tags, list) and tags) else "GenericMalware"
                                })
        except Exception as e:
            logger.error(f"Failed to fetch live URLhaus feed: {e}")
        return items[:limit]

    async def fetch_threatfox_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch recent live IOCs from abuse.ch ThreatFox open feed."""
        items = []
        headers = {"User-Agent": "CampaignX-AI-ThreatPlatform/1.0"}
        try:
            async with httpx.AsyncClient(headers=headers, follow_redirects=True, timeout=10.0) as client:
                res = await client.get("https://threatfox.abuse.ch/export/json/recent/")
                if res.status_code == 200:
                    data = res.json()
                    for key, ioc_list in data.items():
                        if isinstance(ioc_list, list):
                            for item in ioc_list[:limit]:
                                ioc_val = item.get("ioc_value")
                                ioc_type = item.get("ioc_type", "indicator")
                                threat_desc = item.get("threat_type", "botnet_cc")
                                malware = item.get("malware_printable") or item.get("malware") or "Unknown Trojan"
                                actor = item.get("malware_alias") or "Unattributed Syndicate"
                                raw_tags = item.get("tags") or ""
                                tags = [t.strip() for t in raw_tags.split(",")] if isinstance(raw_tags, str) else (raw_tags or [])

                                raw_msg = (
                                    f"[ACTIVE IOC TELEMETRY] {ioc_type.upper()} {ioc_val} identified in real-time.\n"
                                    f"Associated Threat: {threat_desc}\n"
                                    f"Malware Family: {malware}\n"
                                    f"Attributed Threat Actor: {actor}\n"
                                    f"Confidence Score: {item.get('confidence_level', 90)}%\n"
                                    f"Tags: {', '.join(tags) if tags else 'C2_Infrastructure'}"
                                )
                                items.append({
                                    "source": "ThreatFox_Live_Feed",
                                    "channel": "c2_infrastructure",
                                    "language": "english",
                                    "raw_content": raw_msg,
                                    "ioc": ioc_val,
                                    "tags": tags,
                                    "threat": threat_desc,
                                    "actor": actor if actor != "Unattributed Syndicate" else None,
                                    "malware": malware
                                })
        except Exception as e:
            logger.error(f"Failed to fetch live ThreatFox feed: {e}")
        return items[:limit]

    async def sync_live_feeds(self, max_items: int = 30) -> Dict[str, Any]:
        """
        Fetches live real-time feeds from all online connectors and ingests
        them as incidents, correlates campaigns, and updates the threat graph.
        """
        urlhaus_items = await self.fetch_urlhaus_recent(limit=max_items // 2)
        threatfox_items = await self.fetch_threatfox_recent(limit=max_items // 2)
        all_items = urlhaus_items + threatfox_items

        if not all_items:
            return {
                "status": "warning",
                "message": "No live feed items retrieved from upstream connectors. Upstream APIs may be unreachable.",
                "ingested_count": 0
            }

        db: Session = SessionLocal()
        ingested_count = 0
        new_campaigns_created = 0

        try:
            for item in all_items:
                # Check for duplicate raw content
                existing = db.query(Incident).filter(Incident.raw_content == item["raw_content"]).first()
                if existing:
                    continue

                # 1. Scam DNA Extraction
                dna_schema = extract_scam_dna(item["raw_content"], channel=item["channel"])
                extracted_entities = extract_and_resolve_entities(item["raw_content"])

                # 2. Assign or Create Campaign
                campaign_name = f"{item['malware']} Threat Infrastructure Campaign"
                camp = db.query(Campaign).filter(Campaign.name == campaign_name).first()
                if not camp:
                    camp_code = f"CAM-LIVE-{uuid.uuid4().hex[:6].upper()}"
                    camp = Campaign(
                        campaign_id=camp_code,
                        name=campaign_name,
                        description=f"Real-time live campaign tracking {item['malware']} via {item['source']}.",
                        status="ACTIVE",
                        risk_score=92.0,
                        campaign_confidence=0.96,
                        shared_infrastructure=dna_schema.domains + dna_schema.phone_numbers + dna_schema.upi_ids,
                        behavioral_overlap={"tactics": [item["threat"]], "languages": ["english"]}
                    )
                    db.add(camp)
                    db.flush()
                    new_campaigns_created += 1

                # 3. Create Incident
                inc_count = db.query(Incident).count()
                inc_code = f"INC-{inc_count + 1:04d}"

                risk_info = risk_engine.calculate_incident_risk(
                    incident_id=inc_code,
                    dna=dna_schema,
                    has_verified_campaign=True
                )

                incident = Incident(
                    incident_id=inc_code,
                    channel=item["channel"],
                    language=dna_schema.language,
                    raw_content=item["raw_content"],
                    normalized_content=item["raw_content"],
                    source=item["source"],
                    tags=item.get("tags", []),
                    status="analyzed",
                    campaign_id=camp.id
                )
                db.add(incident)
                db.flush()

                # Save Scam DNA
                scam_dna = ScamDNA(
                    incident_id=incident.id,
                    language=dna_schema.language,
                    channel=dna_schema.channel,
                    impersonation_target=dna_schema.impersonation_target,
                    impersonation_target_detail=dna_schema.impersonation_target_detail,
                    urgency=dna_schema.urgency,
                    fear=dna_schema.fear,
                    authority_pressure=dna_schema.authority_pressure,
                    credential_request=dna_schema.credential_request,
                    payment_request=dna_schema.payment_request,
                    payment_method=dna_schema.payment_method,
                    requested_action=dna_schema.requested_action,
                    social_engineering_tactics=dna_schema.social_engineering_tactics,
                    target_type=dna_schema.target_type,
                    script_features=dna_schema.script_features,
                    infrastructure_indicators=dna_schema.infrastructure_indicators,
                    phone_numbers=dna_schema.phone_numbers,
                    upi_ids=dna_schema.upi_ids,
                    urls=dna_schema.urls,
                    domains=dna_schema.domains,
                    emails=dna_schema.emails,
                    extraction_confidence=dna_schema.extraction_confidence
                )
                db.add(scam_dna)

                # Save entities and update Graph
                for ent in extracted_entities:
                    db_ent = db.query(Entity).filter(
                        Entity.type == ent.type,
                        Entity.canonical_value == ent.canonical_value
                    ).first()
                    if not db_ent:
                        db_ent = Entity(
                            type=ent.type,
                            canonical_value=ent.canonical_value,
                            raw_value=ent.raw_value,
                            masked_value=ent.masked_value,
                            risk_score=risk_info["risk_score"]
                        )
                        db.add(db_ent)
                        db.flush()

                    mention = EntityMention(
                        incident_id=incident.id,
                        entity_id=db_ent.id,
                        confidence=ent.confidence
                    )
                    db.add(mention)

                    # Update NetworkX Graph Engine
                    graph_engine.graph.add_node(ent.canonical_value, label=ent.canonical_value, type=ent.type, risk_score=85.0)
                    graph_engine.graph.add_edge(camp.campaign_id, ent.canonical_value, type="USES_INFRASTRUCTURE", confidence=0.90)

                # Push to Real-Time Telemetry Stream Buffer
                stream_event = {
                    "id": incident.incident_id,
                    "source": item["source"],
                    "malware": item["malware"],
                    "threat": item["threat"],
                    "channel": item["channel"],
                    "content_preview": item["raw_content"][:100] + "...",
                    "risk_score": risk_info["risk_score"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                LIVE_STREAM_BUFFER.insert(0, stream_event)
                if len(LIVE_STREAM_BUFFER) > MAX_STREAM_BUFFER:
                    LIVE_STREAM_BUFFER.pop()

                ingested_count += 1

            db.commit()
            logger.info(f"Live feed sync completed: {ingested_count} new incidents ingested, {new_campaigns_created} new campaigns created.")
            return {
                "status": "success",
                "ingested_count": ingested_count,
                "new_campaigns": new_campaigns_created,
                "live_stream_total": len(LIVE_STREAM_BUFFER),
                "synced_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            db.rollback()
            logger.error(f"Live feed ingestion failed: {e}")
            raise e
        finally:
            db.close()

    def get_live_stream(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Returns the latest live stream events."""
        return LIVE_STREAM_BUFFER[:limit]


live_feed_service = LiveFeedService()
