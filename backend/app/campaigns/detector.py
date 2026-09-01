from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import networkx as nx
from backend.app.schemas.scam_dna import ScamDNASchema
from backend.app.correlation.engine import correlation_engine
from backend.app.models import Campaign, Incident, Evidence
from backend.app.evidence.builder import create_canonical_evidence


class CampaignCluster:
    def __init__(self, campaign_id: str, name: str, incidents: List[Dict[str, Any]], shared_infra: List[str]):
        self.campaign_id = campaign_id
        self.name = name
        self.incidents = incidents
        self.shared_infrastructure = shared_infra
        self.incident_count = len(incidents)
        self.first_seen = min([inc.get("timestamp") for inc in incidents]) if incidents else datetime.now(timezone.utc).isoformat()
        self.last_seen = max([inc.get("timestamp") for inc in incidents]) if incidents else datetime.now(timezone.utc).isoformat()
        self.status = "EMERGING" if len(incidents) < 5 else "ACTIVE"
        self.campaign_confidence = min(0.98, 0.80 + (0.03 * min(6, len(incidents))))
        self.risk_score = min(100.0, 70.0 + (5.0 * min(6, len(shared_infra))))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "status": self.status,
            "incident_count": self.incident_count,
            "entity_count": len(self.shared_infrastructure) * 2,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "campaign_confidence": round(self.campaign_confidence, 2),
            "risk_score": round(self.risk_score, 1),
            "shared_infrastructure": self.shared_infrastructure,
            "is_emerging": self.status == "EMERGING"
        }


class CampaignDetectionEngine:
    """
    Graph-based Campaign Clustering & Emerging Campaign Detector.
    Constructs connected components using only DETERMINISTICALLY VERIFIED edges.
    """

    def cluster_incidents(self, incident_records: List[Dict[str, Any]]) -> List[CampaignCluster]:
        """
        Clusters a list of incidents with extracted ScamDNA into verified campaigns.
        """
        G = nx.Graph()
        inc_map = {}

        for inc in incident_records:
            inc_id = inc["incident_id"]
            G.add_node(inc_id)
            inc_map[inc_id] = inc

        # Pairwise correlation with false-positive defense
        n = len(incident_records)
        for i in range(n):
            for j in range(i + 1, n):
                inc_a = incident_records[i]
                inc_b = incident_records[j]
                
                dna_a: ScamDNASchema = inc_a["dna"]
                dna_b: ScamDNASchema = inc_b["dna"]
                
                res = correlation_engine.correlate_incidents(
                    inc_a["incident_id"], dna_a, inc_a.get("raw_content", ""),
                    inc_b["incident_id"], dna_b, inc_b.get("raw_content", "")
                )
                
                if res.is_verified:
                    G.add_edge(
                        inc_a["incident_id"],
                        inc_b["incident_id"],
                        weight=res.relationship_confidence,
                        shared=res.shared_elements
                    )

        # Find connected components with >= 2 incidents
        campaigns: List[CampaignCluster] = []
        camp_idx = 1
        
        for component in nx.connected_components(G):
            if len(component) >= 2:
                comp_incidents = [inc_map[node_id] for node_id in component]
                
                # Aggregate shared infrastructure across the component
                all_phones = set()
                all_upis = set()
                all_domains = set()
                
                for inc in comp_incidents:
                    dna: ScamDNASchema = inc["dna"]
                    all_phones.update(dna.phone_numbers)
                    all_upis.update(dna.upi_ids)
                    all_domains.update(dna.domains)
                    
                shared_infra = [f"Phone:{p}" for p in all_phones] + [f"UPI:{u}" for u in all_upis] + [f"Domain:{d}" for d in all_domains]
                
                # Target brand or tactic
                target_detail = comp_incidents[0]["dna"].impersonation_target_detail or comp_incidents[0]["dna"].impersonation_target.title()
                camp_name = f"{target_detail} Fraud Syndicate Cluster"
                camp_id = f"CAM-{camp_idx:03d}"
                
                campaigns.append(CampaignCluster(camp_id, camp_name, comp_incidents, shared_infra))
                camp_idx += 1

        return campaigns

    def detect_emerging_threats(self, new_incident: Dict[str, Any], existing_incidents: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Evaluates an incoming incident against recent telemetry to trigger 'EMERGING CAMPAIGN DETECTED' alerts.
        """
        dna_new: ScamDNASchema = new_incident["dna"]
        matches = []
        
        for ex in existing_incidents:
            dna_ex: ScamDNASchema = ex["dna"]
            res = correlation_engine.correlate_incidents(
                new_incident["incident_id"], dna_new, new_incident.get("raw_content", ""),
                ex["incident_id"], dna_ex, ex.get("raw_content", "")
            )
            if res.is_verified:
                matches.append({"incident": ex, "result": res})

        if matches:
            shared_all = set()
            for m in matches:
                shared_all.update(m["result"].shared_elements)
            return {
                "alert": "EMERGING CAMPAIGN DETECTED",
                "trigger_incident": new_incident["incident_id"],
                "correlated_incident_count": len(matches) + 1,
                "shared_infrastructure": list(shared_all),
                "confidence": max([m["result"].relationship_confidence for m in matches]),
                "recommended_action": "Isolate associated domains and flag linked payment UPI IDs immediately."
            }
        return None


campaign_detector = CampaignDetectionEngine()
