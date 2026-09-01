import {
  DashboardData,
  CampaignSummary,
  CampaignDetail,
  IncidentItem,
  IOCLookupResponse,
  AIAnalysisResponse,
  EvaluationData,
} from '../types';

const API_BASE = '/api/v1';

export const api = {
  async getHealth() {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  async getDashboard(): Promise<DashboardData> {
    const res = await fetch(`${API_BASE}/stats/dashboard`);
    if (!res.ok) throw new Error('Failed to fetch dashboard metrics');
    return res.json();
  },

  async getCampaigns(status?: string): Promise<{ total: number; items: CampaignSummary[] }> {
    const url = status ? `${API_BASE}/campaigns?status=${status}` : `${API_BASE}/campaigns`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch campaigns');
    return res.json();
  },

  async getCampaign(id: string): Promise<CampaignDetail> {
    const res = await fetch(`${API_BASE}/campaigns/${id}`);
    if (!res.ok) throw new Error('Failed to fetch campaign details');
    return res.json();
  },

  async getCampaignGraph(id: string) {
    const res = await fetch(`${API_BASE}/campaigns/${id}/graph`);
    if (!res.ok) throw new Error('Failed to fetch campaign graph');
    return res.json();
  },

  async getIncidents(skip = 0, limit = 50): Promise<{ total: number; items: IncidentItem[] }> {
    const res = await fetch(`${API_BASE}/incidents?skip=${skip}&limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  },

  async getIncident(id: string) {
    const res = await fetch(`${API_BASE}/incidents/${id}`);
    if (!res.ok) throw new Error('Failed to fetch incident details');
    return res.json();
  },

  async submitIncident(payload: { channel: string; raw_content: string; source?: string }) {
    const res = await fetch(`${API_BASE}/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Failed to submit incident');
    }
    return res.json();
  },

  async lookupIOC(query: string, depth = 2): Promise<IOCLookupResponse> {
    const res = await fetch(`${API_BASE}/ioc/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, depth }),
    });
    if (!res.ok) throw new Error('IOC Lookup failed');
    return res.json();
  },

  async runThreatHunt(seed_indicator: string, mode = 'DEEP', depth = 3) {
    const res = await fetch(`${API_BASE}/hunting`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed_indicator, mode, depth }),
    });
    if (!res.ok) throw new Error('Threat hunting failed');
    return res.json();
  },

  async runAIAnalysis(payload: { query: string; incident_id?: string; campaign_id?: string; context?: any }): Promise<AIAnalysisResponse> {
    const res = await fetch(`${API_BASE}/ai/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('AI investigation query failed');
    return res.json();
  },

  async getGlobalGraph() {
    const res = await fetch(`${API_BASE}/graph/global`);
    if (!res.ok) throw new Error('Failed to fetch global graph');
    return res.json();
  },

  async getAttackTechniques() {
    const res = await fetch(`${API_BASE}/attack/techniques`);
    if (!res.ok) throw new Error('Failed to fetch ATT&CK techniques');
    return res.json();
  },

  async runEvaluation(): Promise<EvaluationData> {
    const res = await fetch(`${API_BASE}/evaluation/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error('Evaluation failed');
    return res.json();
  },

  async syncLiveFeed(limit = 25): Promise<{ status: string; ingested_count: number; new_campaigns: number; live_stream_total: number; synced_at: string }> {
    const res = await fetch(`${API_BASE}/feed/sync?limit=${limit}`, {
      method: 'POST',
    });
    if (!res.ok) throw new Error('Failed to sync live threat feeds');
    return res.json();
  },

  async getFeedStatus(): Promise<any> {
    const res = await fetch(`${API_BASE}/feed/status`);
    if (!res.ok) throw new Error('Failed to get feed status');
    return res.json();
  },

  async getFeedStream(limit = 20): Promise<{ total: number; events: any[] }> {
    const res = await fetch(`${API_BASE}/feed/stream?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch live stream');
    return res.json();
  },
};


