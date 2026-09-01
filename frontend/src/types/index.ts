export interface DashboardSummary {
  total_incidents: number;
  total_campaigns: number;
  active_campaigns: number;
  emerging_campaigns: number;
  total_entities: number;
  threat_actors_tracked: number;
  malware_families: number;
  attack_techniques: number;
}

export interface DashboardData {
  summary: DashboardSummary;
  channel_distribution: Record<string, number>;
  language_distribution: Record<string, number>;
  top_campaigns: CampaignSummary[];
  provider_health: Record<string, string>;
}

export interface CampaignSummary {
  campaign_id: string;
  name: string;
  status: string;
  risk_score: number;
  confidence: number;
  incident_count: number;
}

export interface CampaignDetail {
  id: string;
  campaign_id: string;
  name: string;
  description: string;
  status: string;
  risk_score: number;
  campaign_confidence: number;
  incident_count: number;
  shared_infrastructure: string[];
  behavioral_overlap: Record<string, any>;
  first_seen: string;
  last_seen: string;
  incidents: {
    incident_id: string;
    channel: string;
    language: string;
    preview: string;
    created_at: string;
  }[];
  why_campaign: string[];
}

export interface ScamDNAData {
  language: string;
  channel: string;
  impersonation_target: string;
  impersonation_target_detail?: string;
  urgency: number;
  fear: number;
  authority_pressure: number;
  credential_request: boolean;
  payment_request: boolean;
  payment_method: string;
  requested_action?: string;
  social_engineering_tactics: string[];
  script_features: string[];
  phone_numbers: string[];
  upi_ids: string[];
  urls: string[];
  domains: string[];
  extraction_confidence: number;
}

export interface IncidentItem {
  id: string;
  incident_id: string;
  channel: string;
  language: string;
  raw_content: string;
  campaign_id?: string;
  campaign_name?: string;
  created_at: string;
}

export interface IOCLookupResponse {
  query: string;
  detected_type: string;
  canonical_value: string;
  masked_value: string;
  risk_assessment: {
    risk_score: number;
    severity: string;
    malicious_engines: number;
  };
  intelligence: {
    malware_family?: string;
    associated_actors: string[];
    mitre_techniques: string[];
  };
  providers: {
    provider_name: string;
    status: string;
    verdict: string;
    score: number;
    detections: number;
    total_engines: number;
    message?: string;
  }[];
  graph: {
    nodes: any[];
    edges: any[];
    stats: { node_count: number; edge_count: number; density: number };
  };
}

export interface AIAnalysisResponse {
  summary: string;
  evidence_text: string;
  analysis_text: string;
  confidence_score: number;
  limitations_text: string;
  next_steps_text: string;
  provider_used: string;
  model_name: string;
}

export interface EvaluationData {
  status: string;
  dataset_size: number;
  metrics: {
    scam_dna_precision: number;
    scam_dna_recall: number;
    scam_dna_f1: number;
    entity_resolution_precision: number;
    entity_resolution_recall: number;
    campaign_precision: number;
    campaign_recall: number;
    campaign_f1: number;
    false_campaign_rate: number;
    latency: {
      p50_ms: number;
      p95_ms: number;
      p99_ms: number;
    };
  };
  confusion_matrix: {
    true_positives: number;
    false_positives: number;
    true_negatives: number;
    false_negatives: number;
  };
  parameter_sweep: {
    optimal_correlation_threshold: number;
    optimal_jaccard_weight: number;
    recommendation: string;
  };
}
